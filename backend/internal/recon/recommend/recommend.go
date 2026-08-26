// Package recommend — 엔드포인트별 AI 탐지기 추천 (HITL, 스캔 시작 전 사람 검토용).
//
// 오늘의 스캔은 선택한 탐지기 전체를 캡처된 엔드포인트 전체에 곱해서 돈다(30 endpoints ×
// 23 detectors = 690 스텝 식). 이 패키지는 캡처된 대상 전체를 한 번의 배치 LLM 호출로 보여주고
// "이 엔드포인트엔 이 탐지기들이 관련 있어 보인다"를 추천한다. 실제 스캔 실행 여부·최종
// 탐지기 선택은 항상 사람이 검토한 뒤 결정한다(scanengine.Options.PerTarget) — 여기서는
// 초안만 만든다.
//
// classify 패키지(정찰 의미 분류, 이슈 #41)와 같은 원칙: 파라미터는 이름·위치·타입만 보내고
// 값은 절대 보내지 않는다. LLM 이 없거나 실패하면 mechanicalRecommend(규칙 기반 결정론적 추천)로
// fail-open해 "일단 스캔은 막지 않되" 여전히 엔드포인트 모양에 맞는 추천을 낸다(카탈로그 전체
// 덤프가 아니다).
package recommend

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"proxypoc/internal/detector"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/llm"
)

// recommendTimeout — 배치 하나에 대상 전체를 실어 보내는 호출이라 llm 패키지 기본(60초)보다
// 여유를 둔다. ctx에 이미 데드라인이 없을 때만 적용되므로 다른 LLM 호출(판단·트리아지)에는
// 영향이 없다.
const recommendTimeout = 180 * time.Second

// ParamShape — LLM 입력용 파라미터 모양(키만, 값 없음).
type ParamShape struct {
	Name string `json:"name"`
	In   string `json:"in"`
	Type string `json:"type,omitempty"`
}

// Item — 대상 1건의 추천 결과.
type Item struct {
	Key         string   `json:"key"` // endpoints.Target.Key() — 추천↔스캔 시작 두 호출을 잇는 식별자
	Host        string   `json:"host"`
	Path        string   `json:"path"`
	Methods     []string `json:"methods,omitempty"`
	Recommended []string `json:"recommended"`        // 비파괴 탐지기 ID만(카탈로그 allow-list 필터 통과분)
	Fallback    bool     `json:"fallback,omitempty"` // 이 항목만 개별 폴백(LLM 응답에서 누락된 키 또는 전체 폴백)
	Reason      string   `json:"reason,omitempty"`   // 왜 이 탐지기들인지(LLM 근거 또는 폴백 사유)
}

// Result — 배치 추천 결과.
type Result struct {
	Items    []Item `json:"items"`
	Source   string `json:"source"`             // "llm" | "fallback"
	Degraded bool   `json:"degraded"`           // 전체 폴백(무프로바이더·오류·파싱실패) — UI 배너용
	Reason   string `json:"reason,omitempty"`
	Provider string `json:"provider,omitempty"`
}

// Recommend — 캡처된 대상 전체를 한 번의 배치 LLM 호출로 추천한다. LLM 응답은 항상
// mechanicalRecommend(결정론적 규칙 계산)와 합집합으로 합쳐진다 — 로컬 소형 모델이 규칙을
// 놓쳐도(실측: 파라미터 있는 엔드포인트를 정적 자산으로 오분류) 최소한은 항상 맞게 보장한다.
// 실패 시(무프로바이더·호출오류·파싱실패)에도 mechanicalRecommend만으로 fail-open한다
// (llm.Judge/Review 와 동일한 fail-open 원칙이지만, "카탈로그 전체 덤프" 대신 규칙 기반 추천).
func Recommend(ctx context.Context, targets []endpoints.Target, catalog []detector.Info) Result {
	allowIDs := nonDestructiveIDs(catalog) // 파괴적 탐지기는 애초에 LLM 에게 보이지도 않는다
	allowSet := toSet(allowIDs)

	if len(targets) == 0 {
		return Result{Items: nil, Source: "fallback"}
	}
	if !llm.Available() {
		return fallbackAll(targets, allowSet, "프로바이더 없음 — 규칙 기반 기본값 사용")
	}

	rctx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, recommendTimeout)
		defer cancel()
	}
	content, err := llm.Complete(rctx, recommendSys(allowIDs), recommendUser(targets))
	if err != nil {
		return fallbackAll(targets, allowSet, "프로바이더 오류("+err.Error()+") — 규칙 기반 기본값 사용")
	}

	var parsed struct {
		Items []struct {
			Key       string   `json:"key"`
			Detectors []string `json:"detectors"`
			Reason    string   `json:"reason"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(extractJSON(content)), &parsed) != nil {
		return fallbackAll(targets, allowSet, "추천 응답 파싱 실패 — 규칙 기반 기본값 사용")
	}

	type entry struct {
		detectors []string
		reason    string
	}
	byKey := map[string]entry{}
	for _, it := range parsed.Items {
		byKey[it.Key] = entry{detectors: it.Detectors, reason: it.Reason}
	}

	seenHost := map[string]bool{} // openssl-tls/sslscan 은 호스트당 한 엔드포인트에만 싣는다
	items := make([]Item, 0, len(targets))
	for _, t := range targets {
		key := t.Key()
		includeTLS := !seenHost[t.Host]
		seenHost[t.Host] = true
		mech := mechanicalRecommend(t, allowSet, includeTLS)

		e, ok := byKey[key]
		if !ok { // LLM이 이 대상을 누락 — 이 항목만 개별 폴백(전체 Degraded는 아님)
			items = append(items, Item{Key: key, Host: t.Host, Path: t.Path, Methods: t.Methods,
				Recommended: mech, Fallback: true, Reason: "LLM 응답에 이 엔드포인트 누락 — 규칙 기반 기본값 사용"})
			continue
		}
		merged := dedupe(append(mech, filterAllowed(e.detectors, allowSet)...)) // 환각/파괴성 id 는 조용히 버림
		items = append(items, Item{Key: key, Host: t.Host, Path: t.Path, Methods: t.Methods,
			Recommended: merged, Reason: e.reason})
	}
	return Result{Items: items, Source: "llm", Provider: llm.ProviderName()}
}

func fallbackAll(targets []endpoints.Target, allowSet map[string]bool, reason string) Result {
	seenHost := map[string]bool{}
	items := make([]Item, 0, len(targets))
	for _, t := range targets {
		includeTLS := !seenHost[t.Host]
		seenHost[t.Host] = true
		items = append(items, Item{Key: t.Key(), Host: t.Host, Path: t.Path, Methods: t.Methods,
			Recommended: mechanicalRecommend(t, allowSet, includeTLS), Fallback: true, Reason: reason})
	}
	return Result{Items: items, Source: "fallback", Degraded: true, Reason: reason}
}

// mechanicalRecommend — recommendSys의 규칙 1~10을 코드로도 그대로 계산한다(결정론적 최소 보장).
// Recommend()에서 LLM 응답과 항상 합집합으로 합쳐진다: 로컬 소형 모델이 규칙을 놓쳐도(실측 —
// 파라미터 있는 엔드포인트를 정적 자산으로 오분류) 이 함수가 계산한 만큼은 항상 보장된다.
// LLM이 없거나 실패했을 때도 그대로 fail-open 기본값으로 쓴다(카탈로그 전체 덤프 대신).
func mechanicalRecommend(t endpoints.Target, allow map[string]bool, includeTLS bool) []string {
	add := func(out []string, ids ...string) []string {
		for _, id := range ids {
			if allow[id] {
				out = append(out, id)
			}
		}
		return out
	}

	var out []string
	if len(t.Params) == 0 && isStaticAssetPath(t.Path) { // 규칙 10 — 정적 자산은 baseline만
		return add(out, "sec-headers", "http-method", "cookie-security")
	}

	out = add(out, "sec-headers", "http-method", "cookie-security") // 규칙 1
	if len(t.Params) > 0 {                                          // 규칙 2
		out = add(out, "reflected-input", "sqli", "sqli-blind", "dom-xss")
	}
	for _, p := range t.Params {
		name := strings.ToLower(p.Name)
		switch {
		case containsAny(name, "file", "path", "filename", "doc", "page"): // 규칙 3
			out = add(out, "path-traversal")
		case containsAny(name, "url", "redirect", "next", "return", "callback"): // 규칙 4
			out = add(out, "open-redirect", "ssrf")
		case containsAny(name, "cmd", "exec", "query", "filter", "template"): // 규칙 5
			out = add(out, "cmd-injection", "ssti", "ldap-injection", "ssi-injection", "xxe")
		}
	}
	if t.Auth { // 규칙 6
		out = add(out, "idor", "privesc", "sensitive-data")
	}
	for _, l := range t.Labels { // 규칙 7
		switch l {
		case "admin":
			out = add(out, "idor", "privesc")
		case "pii", "payment":
			out = add(out, "sensitive-data")
		}
	}
	if isStateChangingMethod(firstMethod(t.Methods)) { // 규칙 8
		out = add(out, "csrf")
	}
	if isDirLikePath(t.Path) { // 규칙 9
		out = add(out, "dir-indexing")
	}
	if includeTLS { // 규칙 12
		out = add(out, "openssl-tls", "sslscan")
	}
	return dedupe(out)
}

var staticExt = []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".css", ".js", ".woff", ".woff2", ".ttf", ".map"}

func isStaticAssetPath(path string) bool {
	lp := strings.ToLower(path)
	for _, ext := range staticExt {
		if strings.HasSuffix(lp, ext) {
			return true
		}
	}
	return false
}

// isDirLikePath — 진짜 디렉터리 나열 후보만 골라낸다. 확장자 없는 REST 스타일 경로
// (/admin, /orders, /product 등)는 대부분 애플리케이션 라우트지 파일시스템 디렉터리가
// 아니라서, "확장자 없음"만으로 판단하면 거의 모든 경로에 dir-indexing 이 붙어버린다(실측).
func isDirLikePath(path string) bool {
	return strings.HasSuffix(path, "/")
}

func isStateChangingMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "POST", "PUT", "DELETE", "PATCH":
		return true
	}
	return false
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// dedupe — 순서는 유지하되 중복 id 제거(mechanical+LLM 합집합용).
func dedupe(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func nonDestructiveIDs(catalog []detector.Info) []string {
	out := make([]string, 0, len(catalog))
	for _, d := range catalog {
		if !d.Destructive {
			out = append(out, d.ID)
		}
	}
	return out
}

func toSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// filterAllowed — allow 에 없는 id(환각·파괴성)는 조용히 버린다.
func filterAllowed(ids []string, allow map[string]bool) []string {
	var out []string
	for _, id := range ids {
		if allow[id] {
			out = append(out, id)
		}
	}
	return out
}

// ── LLM ─────────────────────────────────────────────────────────────

// recommendSys — 시스템 프롬프트. 카탈로그를 id 나열로 준다(토큰 절감을 위해 이름 생략).
//
// "When unsure, include" 한 줄짜리 기준만으로는 로컬 소형 모델(qwen2.5:3b 등)이 파라미터·라벨을
// 활용한 변별을 못 하고 매 엔드포인트에 카탈로그 전체를 반복하는 경향이 있었다(실측). 구체적인
// 신호→탐지기 매핑 규칙을 명시해 "패턴 매칭"에 가깝게 만들고, baseline(항상 포함)과 조건부
// 항목을 분리한다 — 판단·트리아지 프롬프트와 같은 원칙(양방향 기준: 넣을 때/뺄 때를 각각 명시).
func recommendSys(allowIDs []string) string {
	var b strings.Builder
	b.WriteString("You are a security-scan planner assigning detector ids to HTTP endpoints, given a JSON array of endpoints ")
	b.WriteString("(key, method, path, parameter names+location+type only — never values — plus semantic labels and auth-required) ")
	b.WriteString("and a catalog of non-destructive detector ids. Follow these rules mechanically, in order:\n")
	b.WriteString("1. Baseline, always include for every endpoint: sec-headers, http-method, cookie-security.\n")
	b.WriteString("2. If the endpoint has ANY params (query/body/path), also include: reflected-input, sqli, sqli-blind, dom-xss.\n")
	b.WriteString("3. A param name suggesting a file/path (file, path, filename, doc, page) -> add path-traversal.\n")
	b.WriteString("4. A param name suggesting a URL/redirect target (url, redirect, next, return, callback) -> add open-redirect, ssrf.\n")
	b.WriteString("5. A param name suggesting raw command/query/template input (cmd, exec, query, filter, template) -> add cmd-injection, ssti, ldap-injection, ssi-injection, xxe.\n")
	b.WriteString("6. auth-required=true -> add idor, privesc, sensitive-data.\n")
	b.WriteString("7. label \"admin\" -> add idor, privesc. label \"pii\" or \"payment\" -> add sensitive-data.\n")
	b.WriteString("8. ONLY if method is POST, PUT, DELETE, or PATCH -> add csrf. Never add csrf for GET, HEAD, or OPTIONS.\n")
	b.WriteString("9. Path ends in \"/\" (a real directory-listing candidate) -> add dir-indexing. An extensionless REST route like /admin or /orders is NOT a directory — do not add dir-indexing just because it lacks an extension.\n")
	b.WriteString("10. A static asset path with no params (image/css/js/font extension) -> ONLY the baseline from rule 1, skip everything else.\n")
	b.WriteString("11. sqli-time is much slower than other checks — only include it if you already included sqli or sqli-blind for this endpoint AND the params clearly look database-backed (id/search/filter-like); otherwise omit it.\n")
	b.WriteString("12. openssl-tls and sslscan test the whole host's TLS config, not this one endpoint — include them for only ONE endpoint per distinct host in the input, skip for that host's other endpoints.\n")
	b.WriteString("Only use ids from the given catalog — never invent new ids. If no rule above applies to an endpoint, use only the rule-1 baseline for it. ")
	b.WriteString(`Reply with ONLY compact JSON: {"items":[{"key":string,"detectors":[string,...],"reason":string}, ...]} covering every input key exactly once. `)
	b.WriteString(`"reason" is a short Korean phrase (under 15 words) naming the concrete rule/signal used (e.g. "id 파라미터 있어 idor/sqli 후보"). `)
	b.WriteString("Catalog ids: " + strings.Join(allowIDs, ", "))
	return b.String()
}

// recommendUser — 대상 목록을 값 없이 직렬화(키·위치·타입·라벨·인증여부만).
func recommendUser(targets []endpoints.Target) string {
	type epIn struct {
		Key    string       `json:"key"`
		Method string       `json:"method"`
		Path   string       `json:"path"`
		Params []ParamShape `json:"params,omitempty"`
		Labels []string     `json:"labels,omitempty"`
		Auth   bool         `json:"auth,omitempty"`
	}
	eps := make([]epIn, 0, len(targets))
	for _, t := range targets {
		var ps []ParamShape
		for _, p := range t.Params {
			ps = append(ps, ParamShape{Name: p.Name, In: p.In, Type: p.Type})
		}
		eps = append(eps, epIn{Key: t.Key(), Method: firstMethod(t.Methods), Path: t.Path, Params: ps, Labels: t.Labels, Auth: t.Auth})
	}
	b, _ := json.Marshal(eps)
	return string(b)
}

func firstMethod(ms []string) string {
	if len(ms) == 0 {
		return "GET"
	}
	return ms[0]
}

// extractJSON — 응답에서 첫 { … 마지막 } 구간만(모델이 앞뒤로 말을 붙이는 경우). classify.go 와 동일.
func extractJSON(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i < 0 || j < 0 || j < i {
		return s
	}
	return s[i : j+1]
}
