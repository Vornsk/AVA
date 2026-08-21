// Package classify — 정찰 엔드포인트 의미 분류 (이슈 #41).
//
// endpoints 트리는 엔드포인트를 구조적으로만 안다(경로·메서드·파라미터). "이게 결제인가
// 관리자인가 PII 처리인가" 하는 의미는 모른다. 이 의미 계층은 규제 매핑(E5)·스캔 우선순위·
// 위험도 평가의 전제다.
//
// 접근:
//   - 명백한 패턴은 결정론적 룰로 확정한다(/login→auth, /admin/*→admin). 무료·즉시·재현 가능.
//   - 룰이 의미 라벨을 못 잡은 모호한 경우에만 LLM 을 부른다(있을 때만). 토큰을 아끼려고
//     값·응답은 절대 넣지 않는다 — 경로·메서드·파라미터 "키"만 보낸다.
//   - 결과는 시그니처로 캐시한다(llm.Judge 와 같은 패턴). 같은 (메서드,경로꼴,키)는 한 번만.
//
// 라벨은 노드 단위로 endpoints.SetLabels 에 저장돼 출처·파라미터와 직교한다(E5/E6 가 읽는다).
package classify

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/llm"
)

// 의미 라벨 (착수 합의 ① — E5 규제 매핑과 정렬). 한 엔드포인트는 여러 라벨을 가질 수 있다.
const (
	Auth    = "auth"    // 로그인·세션·토큰·비밀번호
	Payment = "payment" // 결제·주문·정산·지갑
	Upload  = "upload"  // 파일 업로드·임포트
	Admin   = "admin"   // 관리자·백오피스·시스템 설정
	PII     = "pii"     // 개인정보(프로필·계정·KYC)
	Search  = "search"  // 검색·조회·자동완성
	API     = "api"     // 구조적: API/REST/GraphQL/버전 경로
	Static  = "static"  // 구조적: 정적 자원
	Other   = "other"   // 어느 것도 아님
)

// semantic — 룰이 이 중 하나라도 잡으면 "확정"으로 보고 LLM 을 부르지 않는다(착수 합의 ④).
// api·static·other 는 구조적 추정이라 확정으로 치지 않는다.
var semantic = map[string]bool{Auth: true, Payment: true, Upload: true, Admin: true, PII: true, Search: true}

// known — LLM 이 돌려준 라벨 중 이 집합에 없는 것은 버린다(환각 방지).
var known = map[string]bool{
	Auth: true, Payment: true, Upload: true, Admin: true, PII: true, Search: true, API: true, Static: true, Other: true,
}

// Input — 분류 입력. ★ 토큰 절감: 값·응답은 없다. 경로·메서드·파라미터 키만.
type Input struct {
	Method    string
	Path      string
	ParamKeys []string
}

// Result — 분류 1건.
type Result struct {
	Labels []string
	From   string // "rule" | "llm" | "cache"
}

// Report — 트리 1회 분류 결과.
type Report struct {
	Endpoints int      `json:"endpoints"` // 분류한 엔드포인트 수
	Labeled   int      `json:"labeled"`   // 라벨이 하나라도 붙은 수
	RuleHits  int      `json:"rule_hits"` // 룰만으로 확정한 수
	LLMHits   int      `json:"llm_hits"`  // LLM 을 부른 수
	Cached    int      `json:"cached"`    // 캐시로 처리한 수
	Duration  string   `json:"duration"`
	Sample    []string `json:"sample,omitempty"` // "METHOD path → labels" 일부
}

// maxLLM — 한 번의 Run 에서 부를 LLM 최대 호출 수(비용 방어). 캐시가 중복은 이미 걷어낸다.
const maxLLM = 100

var (
	cacheMu sync.Mutex
	cache   = map[string]Result{}
)

// sig — 캐시 키. 값이 아니라 (메서드, 경로꼴, 정렬된 키)만. 같은 꼴은 한 번만 분류한다.
func sig(in Input) string {
	keys := append([]string(nil), in.ParamKeys...)
	sort.Strings(keys)
	return strings.ToUpper(in.Method) + " " + endpoints.NormalizePath(in.Path) + " [" + strings.Join(keys, ",") + "]"
}

// Classify — 한 엔드포인트를 분류한다. 룰 우선, 모호하면(그리고 프로바이더가 있으면) LLM.
// 예산 없는 단건 분류 = classifyBudgeted(호출당 LLM 최대 1회).
func Classify(ctx context.Context, in Input) Result {
	budget := 1
	return classifyBudgeted(ctx, in, &budget)
}

// Run — 트리의 대상 엔드포인트를 분류해 라벨을 붙인다.
func Run(ctx context.Context, tree *endpoints.Tree) Report {
	start := time.Now()
	rep := Report{}
	llmLeft := maxLLM
	for _, t := range tree.Targets() {
		if ctx.Err() != nil {
			break
		}
		in := Input{Method: firstMethod(t.Methods), Path: t.Path, ParamKeys: paramNames(t.Params)}
		res := classifyBudgeted(ctx, in, &llmLeft)

		rep.Endpoints++
		switch res.From {
		case "cache":
			rep.Cached++
		case "llm":
			rep.LLMHits++
		default:
			rep.RuleHits++
		}
		if len(res.Labels) > 0 && !(len(res.Labels) == 1 && res.Labels[0] == Other) {
			rep.Labeled++
		}
		tree.SetLabels(t.Host, t.Path, res.Labels)
		if len(rep.Sample) < 20 {
			rep.Sample = append(rep.Sample, in.Method+" "+t.Path+" → "+strings.Join(res.Labels, ","))
		}
	}
	tree.Persist() // 라벨을 인메모리로 다 붙인 뒤 한 번만 파일에 반영(엔드포인트마다 덤프 방지)
	rep.Duration = time.Since(start).String()
	return rep
}

// classifyBudgeted — Run 내부용. 캐시 우선 → 룰 → (예산·프로바이더 있고 모호하면) LLM.
// ruleLabels 를 한 번만 계산하고, LLM 을 실제로 부를 때만 예산을 깎는다.
func classifyBudgeted(ctx context.Context, in Input, llmLeft *int) Result {
	key := sig(in)
	cacheMu.Lock()
	if r, ok := cache[key]; ok {
		cacheMu.Unlock()
		return Result{Labels: r.Labels, From: "cache"}
	}
	cacheMu.Unlock()

	ruled, confident := ruleLabels(in)
	var res Result
	if confident || *llmLeft <= 0 || !llm.Available() {
		res = Result{Labels: fallback(ruled), From: "rule"}
	} else {
		*llmLeft--
		res = Result{Labels: mergeLabels(ruled, llmLabels(ctx, in)), From: "llm"}
	}
	cacheMu.Lock()
	cache[key] = res
	cacheMu.Unlock()
	return res
}

// ── 룰 ──────────────────────────────────────────────────────────────

var reVersionSeg = regexp.MustCompile(`^v\d+$`)

// pathKeywords — 경로 세그먼트가 포함하면 해당 라벨. (부분문자열 매칭, 세그먼트 단위)
var pathKeywords = map[string][]string{
	Auth:    {"login", "logout", "signin", "signup", "register", "auth", "oauth", "sso", "session", "password", "passwd", "credential", "mfa", "otp", "2fa", "token", "verify"},
	Payment: {"pay", "payment", "checkout", "order", "billing", "invoice", "charge", "refund", "subscription", "wallet", "transfer", "remit", "settlement", "card"},
	Upload:  {"upload", "import", "attachment", "avatar", "photo", "media"},
	Admin:   {"admin", "administrator", "manage", "management", "backoffice", "console", "superuser", "internal", "sysconfig"},
	PII:     {"profile", "account", "customer", "member", "user", "kyc", "identity", "ssn", "passport", "personal"},
	Search:  {"search", "query", "lookup", "autocomplete", "suggest", "typeahead"},
}

// paramKeywords — 파라미터 키가 이 중 하나면 해당 라벨.
var paramKeywords = map[string][]string{
	Auth:    {"password", "passwd", "otp", "token", "session", "auth"},
	Payment: {"amount", "card", "cardnumber", "cvv", "cvc", "iban", "account", "price", "currency"},
	Upload:  {"file", "filename", "upload", "attachment"},
	PII:     {"ssn", "email", "phone", "birth", "birthday", "dob", "address", "firstname", "lastname"},
	Search:  {"q", "query", "keyword", "term", "search"},
}

// ruleLabels — 결정론적 라벨과 "확정 여부"(의미 라벨을 잡았는가)를 돌려준다.
func ruleLabels(in Input) (labels []string, confident bool) {
	p := strings.ToLower(in.Path)
	segs := strings.Split(p, "/")
	set := map[string]bool{}

	// 구조적
	if isStaticPath(segs) {
		set[Static] = true
	}
	for _, s := range segs {
		if s == "api" || s == "rest" || s == "graphql" || reVersionSeg.MatchString(s) {
			set[API] = true
			break
		}
	}
	// 의미 — 경로 세그먼트 부분문자열
	for label, kws := range pathKeywords {
		if segContainsAny(segs, kws) {
			set[label] = true
		}
	}
	// 의미 — 파라미터 키
	lk := lowerSet(in.ParamKeys)
	for label, keys := range paramKeywords {
		for _, k := range keys {
			if lk[k] {
				set[label] = true
				break
			}
		}
	}

	for l := range set {
		labels = append(labels, l)
		if semantic[l] {
			confident = true
		}
	}
	sort.Strings(labels)
	return labels, confident
}

var staticExt = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".webp": true,
	".pdf": true, ".mp4": true, ".webm": true, ".wasm": true,
}
var staticSeg = map[string]bool{"static": true, "assets": true, "public": true, "dist": true, "fonts": true, "img": true, "images": true}

func isStaticPath(segs []string) bool {
	for _, s := range segs {
		if staticSeg[s] {
			return true
		}
		if i := strings.LastIndex(s, "."); i >= 0 && staticExt[s[i:]] {
			return true
		}
	}
	return false
}

func segContainsAny(segs, kws []string) bool {
	for _, s := range segs {
		for _, k := range kws {
			if strings.Contains(s, k) {
				return true
			}
		}
	}
	return false
}

func lowerSet(keys []string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[strings.ToLower(k)] = true
	}
	return m
}

// fallback — 라벨이 하나도 없으면 other 로. 있으면 그대로.
func fallback(ls []string) []string {
	if len(ls) == 0 {
		return []string{Other}
	}
	return ls
}

// mergeLabels — 룰 라벨과 LLM 라벨을 합집합(정렬·중복 제거). 비면 other.
func mergeLabels(a, b []string) []string {
	set := map[string]bool{}
	for _, l := range a {
		set[l] = true
	}
	for _, l := range b {
		if known[l] {
			set[l] = true
		}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return fallback(out)
}

// ── LLM ─────────────────────────────────────────────────────────────

const classifySys = "You are an endpoint-classifier. Given an HTTP endpoint (method, path, parameter names only — never values), " +
	"return JSON {\"labels\":[...]} choosing zero or more of: auth, payment, upload, admin, pii, search, api, static, other. " +
	"Judge purpose from the path and parameter names. Return only the JSON."

// classifyUser — LLM 사용자 프롬프트. ★ 값·응답 없음. 경로·메서드·키만.
func classifyUser(in Input) string {
	keys := append([]string(nil), in.ParamKeys...)
	sort.Strings(keys)
	return "method: " + strings.ToUpper(in.Method) + "\npath: " + in.Path + "\nparam_keys: [" + strings.Join(keys, ", ") + "]"
}

// llmLabels — 프로바이더에 분류를 물어 known 라벨만 돌려준다. 오류·파싱실패면 nil(룰로 폴백).
func llmLabels(ctx context.Context, in Input) []string {
	content, err := llm.Complete(ctx, classifySys, classifyUser(in))
	if err != nil {
		return nil
	}
	var parsed struct {
		Labels []string `json:"labels"`
	}
	if json.Unmarshal([]byte(extractJSON(content)), &parsed) != nil {
		return nil
	}
	var out []string
	for _, l := range parsed.Labels {
		l = strings.ToLower(strings.TrimSpace(l))
		if known[l] {
			out = append(out, l)
		}
	}
	return out
}

// extractJSON — 응답에서 첫 { … 마지막 } 구간만 (모델이 앞뒤로 말을 붙이는 경우).
func extractJSON(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i < 0 || j < 0 || j < i {
		return s
	}
	return s[i : j+1]
}

// ── helpers ─────────────────────────────────────────────────────────

func paramNames(ps []endpoints.Param) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

func firstMethod(ms []string) string {
	if len(ms) == 0 {
		return "GET"
	}
	return ms[0]
}
