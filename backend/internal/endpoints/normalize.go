// 정찰 정규화 v2 (이슈 #24) — 경로 세그먼트 분류기 + 형제 다양성 클러스터링.
//
// v1 은 숫자-only 세그먼트만 {id} 로 접었다. UUID·해시·날짜·base64 경로가 그대로 남아
// 동일 엔드포인트가 수백 노드로 쪼개졌고(트리 폭발), 스캔 타겟·커버리지 지표가 오염됐다.
//
//	· 분류기(classifyToken) : 숫자→{id}, UUID→{uuid}, hex(≥16)→{hash}, YYYY-MM-DD→{date}, base64-ish→{b64}
//	· 확장자 보존           : main.9f8a7b6c5d4e3f21.js → main.{hash}.js (번들 해시 접기)
//	· 형제 클러스터링       : 같은 부모 밑 리프 자식이 임계치 초과 + 값 다양성 높으면 {slug} 로 접기
//	· inferType 와 규칙 공유 : 숫자·UUID 판정 정규식이 한 곳에만 존재 (중복 제거)
//
// ★ 측정 제약 (이슈 #22/#24): 벤치 하네스의 채점 키(bench.Canon)는 이 파일에 의존하지 않는다.
// 이 이슈의 효과는 트리 팽창률(제품 구분 노드 수 ÷ 하네스 canonical 수)로만 관찰한다.
package endpoints

import (
	"regexp"
	"sort"
	"strings"
)

// 세그먼트 템플릿 토큰.
const (
	tplID   = "{id}"
	tplUUID = "{uuid}"
	tplHash = "{hash}"
	tplDate = "{date}"
	tplB64  = "{b64}"
	tplSlug = "{slug}"
)

// 출처 신뢰도 등급 (이슈 #25 → #26). 값이 클수록 믿을 만하다.
//
// 등급이 필요한 이유는 "실제로 요청해서 2xx 를 받았다"와 "실재한다"가 다르기 때문이다.
// SPA 는 없는 경로에도 200 + index.html 을 주므로, 크롤러가 스스로 만들어낸 요청
// (링크 추종·정규식 추출)은 실재 여부를 따로 확인해야 한다. 반대로 외부에서 들어온
// 트래픽과 앱이 스스로 호출한 XHR 은 실재의 증거 자체다.
const (
	SrcSpec        = "spec"         // 명세 인제스트 (#25) — 프로브 면제
	SrcTraffic     = "traffic"      // 프록시 실캡처 — 프로브 면제
	SrcHeadlessXHR = "headless-xhr" // 헤드리스가 캡처한 XHR/fetch — 프로브 면제
	SrcDiscover    = "discover"     // 능동 발견 (#27) — 등록 전 실재 확인 완료, 프로브 면제
	SrcCrawlLink   = "crawl-link"   // 크롤러가 따라간 링크 — 프로브 대상
	SrcStaticRegex = "static-regex" // JS/HTML 정규식 추출물 — 프로브 대상
)

// srcSpec — 패키지 내부 별칭 (#25 코드 호환).
const srcSpec = SrcSpec

// sourceRank — 출처 등급의 서열. 병합 시 높은 쪽이 이긴다.
// 빈 문자열("")은 출처를 기록하지 않던 시절의 값이자 프록시 캡처의 기본값이라
// traffic 과 같은 등급으로 본다(프로브 면제) — 하위호환.
func sourceRank(src string) int {
	switch src {
	case SrcSpec:
		return 6
	case SrcTraffic, "":
		return 5
	case SrcHeadlessXHR:
		return 4
	case SrcDiscover:
		// 실재는 확인됐지만(등록 전 프로브) 실제로 쓰이는지는 모른다 —
		// 앱이 스스로 호출하는 XHR 보다는 아래, 링크가 가리키는 것보다는 위.
		return 3
	case SrcCrawlLink:
		return 2
	case SrcStaticRegex:
		return 1
	}
	return 0
}

// NeedsProbe — 이 출처가 실재 여부 검증(라이브니스 프로브) 대상인가 (이슈 #26).
func NeedsProbe(src string) bool { return src == SrcCrawlLink || src == SrcStaticRegex }

var (
	reUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	// hex 는 실단어 오폴딩을 피하려 16자 이상만 변수로 간주(세션·토큰·해시). 하네스 Canon 과 동일 기준.
	reHex = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	// base64-ish 는 charset 만으로는 일반 slug(application-configuration)와 구분되지 않는다.
	// → 20자 이상 + 숫자 포함 + 대문자 포함을 모두 요구해 소문자 slug 를 배제한다.
	reB64 = regexp.MustCompile(`^[A-Za-z0-9+/_=-]{20,}$`)

	reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	// 확장자: 마지막 점 뒤 1~5자, 첫 글자는 영문 (js, css, html, json, png …).
	// 숫자로 시작하는 조각은 확장자가 아니라 값이다(버전 1.2.3 의 "3" 을 확장자로 보지 않기 위해).
	reExt = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,4}$`)
)

// classifyToken — 토큰 하나를 템플릿으로 분류한다. 가변값이 아니면 (,false).
// inferType(파라미터 값 타입추정)과 경로 정규화가 공유하는 단일 규칙 지점이다.
func classifyToken(s string) (string, bool) {
	switch {
	case s == "":
		return "", false
	case reDate.MatchString(s): // 날짜가 숫자보다 먼저 (2026-08-18 은 hex 도 숫자도 아님)
		return tplDate, true
	case isAllDigits(s):
		return tplID, true
	case reUUID.MatchString(s):
		return tplUUID, true
	case reHex.MatchString(s): // dash 없는 32자 UUID 도 여기로 (hex ≥16)
		return tplHash, true
	case isBase64ish(s):
		return tplB64, true
	}
	return "", false
}

// isBase64ish — base64/base64url 로 보이는가. 소문자-하이픈 slug 오폴딩 방지용 추가 조건 포함.
func isBase64ish(s string) bool {
	if !reB64.MatchString(s) {
		return false
	}
	var hasDigit, hasUpper bool
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		}
	}
	return hasDigit && hasUpper
}

// classifySegment — 경로 세그먼트 하나를 템플릿으로. 가변값이 아니면 원본 그대로.
// 세그먼트 전체가 분류되지 않으면 점(.)으로 쪼개 부분 분류를 시도한다
// (예: main.9f8a7b6c5d4e3f21.js → main.{hash}.js — 번들 해시).
func classifySegment(s string) string {
	if tpl, ok := classifyToken(s); ok {
		return tpl
	}
	if !strings.Contains(s, ".") {
		return s
	}
	parts := strings.Split(s, ".")
	changed := false
	for i, p := range parts {
		if i == len(parts)-1 && reExt.MatchString(p) {
			continue // 마지막 확장자는 보존 (.js/.json — 파일 타입 정보)
		}
		if tpl, ok := classifyToken(p); ok {
			parts[i] = tpl
			changed = true
		}
	}
	if !changed {
		return s
	}
	return strings.Join(parts, ".")
}

// isTemplate — 이미 접힌 세그먼트인가 ({id}, {slug} …).
func isTemplate(s string) bool {
	return len(s) >= 2 && s[0] == '{' && s[len(s)-1] == '}'
}

// NormalizePath — 가변 세그먼트를 템플릿으로 치환해 중복 제거 (v2, 이슈 #24).
// 엔드포인트 트리와 LLM 토큰최소화 dedup(FR-2.3), 크롤러 방문 키가 공용으로 쓴다.
// 순수 함수 — 형제 클러스터링({slug})은 트리 상태가 필요해 여기가 아니라 foldSiblings 가 한다.
func NormalizePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s == "" || isTemplate(s) {
			continue
		}
		segs[i] = classifySegment(s)
	}
	return strings.Join(segs, "/")
}

// ── 형제 다양성 클러스터링 ────────────────────────────────────────
//
// 같은 부모 밑에 리프 자식이 임계치를 넘도록 많고 값 다양성이 높으면(대부분 1회만 등장)
// 그 자리는 라우트명이 아니라 값(slug)이라고 보고 {slug} 하나로 접는다.
//
// 보수적 설계 (재현율 보호):
//   - 호스트 루트 직속 자식은 접지 않는다. 루트 세그먼트는 대개 최상위 라우트명이라
//     접히면 /metrics, /api 같은 실제 엔드포인트가 통째로 사라진다.
//   - 후보는 자식이 없고(리프) 파라미터도 없고 값처럼 생긴(looksLikeValue) 노드만.
//     공격면(파라미터)이나 하위 구조가 있는 노드는 보존.
//   - 한 번 접힌 부모는 varChild={slug} 로 표시해 이후 같은 자리 값은 바로 흡수한다
//     (다시 12개가 쌓일 때까지 트리가 재팽창하는 것을 막는다).
//
// ★ looksLikeValue 가 없으면 REST 리소스 컬렉션이 통째로 사라진다.
// juice-shop /api 밑에는 Products·Feedbacks·Challenges… 12종 이상이 각각 1회씩만 등장하는
// 리프로 쌓인다. "리프 + 무파라미터 + 고유" 조건만으로는 이들이 slug 값과 구분되지 않아
// /api/{slug} 하나로 접혔고, 하네스 재현율이 41.9% → 22.6% 로 무너졌다(#24 완료기준 3 위반).
const (
	slugMinSiblings     = 12  // 접기 발동 최소 형제 수
	slugMinDistinctRate = 0.8 // 고유비율 = 후보 수 ÷ 후보 총 히트 (재사용 적을수록 값에 가깝다)
	slugMinSeparators   = 2   // 값 표식: 단어 구분자(- _) 이 정도 이상이면 라우트명이 아니라 slug
)

// looksLikeValue — 라우트명이 아니라 값(slug)처럼 생겼는가.
// 라우트명은 대개 한 단어이거나 하이픈 하나로 이어진 짧은 명사구다
// (Products, SecurityQuestions, application-configuration, reset-password).
// 반대로 slug 값은 숫자를 끼거나 단어를 여러 번 잇는다
// (my-first-post, red-nike-shoes-42, order-2026-08-a).
func looksLikeValue(s string) bool {
	seps := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			return true
		case r == '-' || r == '_':
			seps++
		}
	}
	return seps >= slugMinSeparators
}

// absorb — cur 아래에 세그먼트 s 를 넣을 때, 변수 자리로 흡수해야 하는지 판단한다.
// 흡수 대상이면 (변수 세그먼트, true), 아니면 (s, false).
//
//	· 리터럴 우선 — 이미 같은 이름의 자식이 있으면 그쪽이다.
//	  명세가 /users/v1/{username} 과 /users/v1/_debug 를 함께 등록했을 때,
//	  크롤이 만난 /users/v1/_debug 가 {username} 으로 삼켜지면 안 된다.
//	· 명세가 선언한 변수 자리(varSpec)는 값 모양을 따지지 않는다 — 명세가 확정적으로 알려줬다.
//	  반대로 휴리스틱(#24)이 만든 자리는 값처럼 생긴 세그먼트만 흡수한다.
//	· 명세 기록(source=spec) 자신은 흡수되지 않는다 — 명세가 트리 구조의 기준이다.
func absorb(cur *node, s, source string) (string, bool) {
	if source == srcSpec || cur.varChild == "" || isTemplate(s) {
		return s, false
	}
	if _, literal := cur.children[s]; literal {
		return s, false
	}
	if !cur.varSpec && !looksLikeValue(s) {
		return s, false
	}
	return cur.varChild, true
}

// declareVar — 명세가 "이 자리는 변수"라고 선언한다 (이슈 #25).
// 선언 이전에 크롤이 구체값으로 만들어 둔 자식이 있으면 변수 노드로 흡수한다.
// 명세가 등록한 리터럴 형제(source=spec)와 하위 구조·파라미터가 있는 노드는 보존한다 —
// #24 에서 REST 리소스 컬렉션을 통째로 삼켰던 실패의 재발 방지.
func declareVar(parent *node, tpl string) {
	parent.varChild, parent.varSpec = tpl, true
	v := parent.children[tpl]
	if v == nil {
		return
	}
	for seg, ch := range parent.children {
		if isTemplate(seg) || ch.source == srcSpec || len(ch.children) > 0 || len(ch.params) > 0 {
			continue
		}
		mergeNode(v, ch)
		delete(parent.children, seg)
	}
	repath(v, parent.path)
}

// foldSiblings — parent 의 리프 자식들이 조건을 만족하면 {slug} 하나로 병합한다.
// 호출자가 t.mu 를 쥐고 있어야 한다. parent 가 호스트 루트면 아무것도 하지 않는다.
func foldSiblings(parent *node, isHostRoot bool) {
	if isHostRoot {
		return
	}
	var cand []string
	hits := 0
	for seg, ch := range parent.children {
		if isTemplate(seg) || len(ch.children) > 0 || len(ch.params) > 0 || !looksLikeValue(seg) {
			continue
		}
		cand = append(cand, seg)
		hits += ch.count
	}
	if len(cand) == 0 {
		return
	}
	if parent.varChild == "" { // 최초 발동에만 임계치를 요구한다
		if len(cand) < slugMinSiblings {
			return
		}
		if hits > 0 && float64(len(cand))/float64(hits) < slugMinDistinctRate {
			return
		}
	}

	slug := parent.children[tplSlug]
	if slug == nil {
		slug = newNode(tplSlug, parent.path+"/"+tplSlug)
		parent.children[tplSlug] = slug
	}
	for _, seg := range cand {
		mergeNode(slug, parent.children[seg])
		delete(parent.children, seg)
	}
	parent.varChild = tplSlug // 이 자리는 값이다 — 이후 같은 자리 값을 흡수한다
	repath(slug, parent.path)
}

// mergeNode — src 를 dst 에 흡수한다(같은 템플릿으로 접힌 두 노드의 집계 합산).
// 처음부터 한 노드에 기록됐을 때와 같은 상태가 되도록 count·seen 을 더해
// Required(seen == count) 정합을 유지한다.
func mergeNode(dst, src *node) {
	for m := range src.methods {
		dst.methods[m] = true
	}
	for name, sp := range src.params {
		dp := dst.params[name]
		if dp == nil {
			dp = &paramAgg{ins: map[string]bool{}}
			dst.params[name] = dp
		}
		for in := range sp.ins {
			dp.ins[in] = true
		}
		if dp.typ == "" {
			dp.typ = sp.typ
		}
		if dp.sample == "" {
			dp.sample = sp.sample
		}
		dp.seen += sp.seen
	}
	dst.count += src.count
	dst.auth = dst.auth || src.auth
	if dst.verdict == "" {
		dst.verdict = src.verdict
	}
	if dst.firstSeen == "" || (src.firstSeen != "" && src.firstSeen < dst.firstSeen) {
		dst.firstSeen = src.firstSeen
	}
	if src.lastSeen > dst.lastSeen {
		dst.lastSeen = src.lastSeen
	}
	// 재요청용 구체 경로는 더 최근에 본 쪽을 남긴다.
	if dst.lastPath == "" || (src.lastPath != "" && src.lastSeen >= dst.lastSeen) {
		dst.lastPath, dst.scheme = src.lastPath, src.scheme
	}
	// 출처는 더 높은 등급이 이긴다 (이슈 #26). 등급이 2종이던 시절에는 "비어 있으면 채운다"로
	// 충분했지만, 5단계가 되면 static-regex 노드에 traffic 노드가 병합될 때 낮은 등급이 남는다.
	if sourceRank(src.source) > sourceRank(dst.source) {
		dst.source = src.source
	}
	// 하나라도 실재가 확인됐으면 verified 다.
	if !src.unverified {
		dst.unverified = false
	}
	if dst.varChild == "" {
		dst.varChild, dst.varSpec = src.varChild, src.varSpec
	}
	for seg, sc := range src.children {
		if dc := dst.children[seg]; dc != nil {
			mergeNode(dc, sc)
		} else {
			dst.children[seg] = sc
		}
	}
}

// repath — 노드 구조가 바뀐 뒤 path 필드를 부모 기준으로 다시 계산한다.
func repath(n *node, parentPath string) {
	n.path = parentPath + "/" + n.segment
	for _, c := range n.children {
		repath(c, n.path)
	}
}

// ── 하위호환: 로드 시 1회 마이그레이션 ────────────────────────────
//
// v1 로 저장된 endpoints.json 에는 접히지 않은 구체 세그먼트가 남아 있다.
// 그대로 두면 같은 엔드포인트가 /u/550e8400-… 과 /u/{uuid} 두 노드로 공존하므로,
// 로드 직후 한 번 v2 로 재분류하고 같은 템플릿이 된 노드를 병합한다(파일은 다음 Record 때 갱신).

// migrateNode — n 의 자손 세그먼트를 v2 로 재분류·병합하고 형제 클러스터링을 적용한다.
// n 자신의 segment 는 건드리지 않는다(호스트 루트 보호).
func migrateNode(n *node, isHostRoot bool) {
	if len(n.children) == 0 {
		return
	}
	rebuilt := map[string]*node{}
	for _, seg := range sortedChildKeys(n) {
		ch := n.children[seg]
		migrateNode(ch, false)
		ch.segment = classifySegment(seg)
		if ex := rebuilt[ch.segment]; ex != nil {
			mergeNode(ex, ch)
			continue
		}
		rebuilt[ch.segment] = ch
	}
	n.children = rebuilt
	foldSiblings(n, isHostRoot)
}

// sortedChildKeys — 자식 세그먼트 키(정렬). 병합 순서를 결정론적으로 만든다.
func sortedChildKeys(n *node) []string {
	out := make([]string, 0, len(n.children))
	for k := range n.children {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
