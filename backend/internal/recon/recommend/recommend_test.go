package recommend

import (
	"context"
	"strings"
	"testing"
	"time"

	"proxypoc/internal/detector"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/llm"
)

func has(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func sampleCatalog() []detector.Info {
	return []detector.Info{
		{ID: "sqli", Name: "SQL Injection"},
		{ID: "reflected-input", Name: "Reflected Input"},
		{ID: "sec-headers", Name: "Security Headers"},
		{ID: "file-upload", Name: "File Upload", Destructive: true},
	}
}

func sampleTargets() []endpoints.Target {
	return []endpoints.Target{
		{Host: "a.example", Path: "/login", Methods: []string{"POST"}},
		{Host: "a.example", Path: "/search", Methods: []string{"GET"}, Params: []endpoints.Param{{Name: "q", In: "query"}}},
	}
}

type stubProvider struct {
	reply    string
	err      error
	calls    int
	lastSys  string
	lastUser string
}

func (p *stubProvider) Name() string { return "stub" }
func (p *stubProvider) Complete(_ context.Context, system, user string) (string, error) {
	p.calls++
	p.lastSys, p.lastUser = system, user
	return p.reply, p.err
}

// 폴백은 더 이상 "카탈로그 전체 덤프"가 아니라 mechanicalRecommend(결정론적 규칙)다 —
// 파라미터 없는 엔드포인트는 injection 계열을 안 받고, 파라미터 있는 엔드포인트만 받는다.
func TestRecommendNoProviderFallsBackToMechanicalRules(t *testing.T) {
	llm.SetProvider(nil)
	res := Recommend(context.Background(), sampleTargets(), sampleCatalog())
	if res.Source != "fallback" || !res.Degraded {
		t.Fatalf("Source=%q Degraded=%v, want fallback/true", res.Source, res.Degraded)
	}
	if len(res.Items) != 2 {
		t.Fatalf("Items=%d, want 2", len(res.Items))
	}
	byKey := map[string]Item{}
	for _, it := range res.Items {
		byKey[it.Key] = it
		if has(it.Recommended, "file-upload") {
			t.Errorf("Item %s includes destructive id in fallback: %v", it.Key, it.Recommended)
		}
	}
	login := byKey["a.example|/login"] // 파라미터 없음
	if !has(login.Recommended, "sec-headers") {
		t.Errorf("login should at least get the sec-headers baseline: %v", login.Recommended)
	}
	if has(login.Recommended, "sqli") || has(login.Recommended, "reflected-input") {
		t.Errorf("login has no params — should not get injection detectors: %v", login.Recommended)
	}
	search := byKey["a.example|/search"] // q 쿼리 파라미터 있음
	if !has(search.Recommended, "sqli") || !has(search.Recommended, "reflected-input") {
		t.Errorf("search has a param — should get sqli/reflected-input: %v", search.Recommended)
	}
}

func TestRecommendDestructiveNeverOfferedToLLM(t *testing.T) {
	stub := &stubProvider{reply: `{"items":[{"key":"a.example|/login","detectors":["file-upload","sqli"]},{"key":"a.example|/search","detectors":["sqli"]}]}`}
	llm.SetProvider(stub)
	defer llm.SetProvider(nil)

	res := Recommend(context.Background(), sampleTargets(), sampleCatalog())
	if strings.Contains(stub.lastSys, "file-upload") {
		t.Errorf("system prompt exposed destructive id to LLM: %s", stub.lastSys)
	}
	for _, it := range res.Items {
		if has(it.Recommended, "file-upload") {
			t.Errorf("Item %s: destructive id survived filtering: %v", it.Key, it.Recommended)
		}
	}
}

func TestRecommendFiltersHallucinatedIDs(t *testing.T) {
	stub := &stubProvider{reply: `{"items":[{"key":"a.example|/login","detectors":["sqli","made-up-id"]},{"key":"a.example|/search","detectors":["sec-headers"]}]}`}
	llm.SetProvider(stub)
	defer llm.SetProvider(nil)

	res := Recommend(context.Background(), sampleTargets(), sampleCatalog())
	if res.Source != "llm" {
		t.Fatalf("Source=%q, want llm", res.Source)
	}
	for _, it := range res.Items {
		if has(it.Recommended, "made-up-id") {
			t.Errorf("hallucinated id survived: %v", it.Recommended)
		}
	}
}

func TestRecommendParseFailureFallsBack(t *testing.T) {
	stub := &stubProvider{reply: "not json"}
	llm.SetProvider(stub)
	defer llm.SetProvider(nil)

	res := Recommend(context.Background(), sampleTargets(), sampleCatalog())
	if res.Source != "fallback" || !res.Degraded {
		t.Fatalf("Source=%q Degraded=%v, want fallback/true", res.Source, res.Degraded)
	}
}

func TestRecommendHappyPath(t *testing.T) {
	stub := &stubProvider{reply: `{"items":[{"key":"a.example|/login","detectors":["sec-headers"]},{"key":"a.example|/search","detectors":["sqli","reflected-input"]}]}`}
	llm.SetProvider(stub)
	defer llm.SetProvider(nil)

	res := Recommend(context.Background(), sampleTargets(), sampleCatalog())
	if res.Source != "llm" || res.Degraded {
		t.Fatalf("Source=%q Degraded=%v, want llm/false", res.Source, res.Degraded)
	}
	if stub.calls != 1 {
		t.Errorf("calls=%d, want 1 (batched)", stub.calls)
	}
	byKey := map[string]Item{}
	for _, it := range res.Items {
		byKey[it.Key] = it
	}
	if !has(byKey["a.example|/login"].Recommended, "sec-headers") {
		t.Errorf("login item missing sec-headers: %v", byKey["a.example|/login"])
	}
	if !has(byKey["a.example|/search"].Recommended, "sqli") {
		t.Errorf("search item missing sqli: %v", byKey["a.example|/search"])
	}
}

func TestRecommendPartialCoverageFillsPerItemFallback(t *testing.T) {
	// login 키 누락 — search만 응답에 있음.
	stub := &stubProvider{reply: `{"items":[{"key":"a.example|/search","detectors":["sqli"]}]}`}
	llm.SetProvider(stub)
	defer llm.SetProvider(nil)

	res := Recommend(context.Background(), sampleTargets(), sampleCatalog())
	if res.Degraded {
		t.Fatalf("Degraded=true, want false (only a per-item fallback, not global)")
	}
	byKey := map[string]Item{}
	for _, it := range res.Items {
		byKey[it.Key] = it
	}
	login := byKey["a.example|/login"]
	if !login.Fallback {
		t.Errorf("login item should be individually fallback: %+v", login)
	}
	if !has(login.Recommended, "sec-headers") {
		t.Errorf("fallback item should at least get the mechanical baseline: %v", login.Recommended)
	}
	if has(login.Recommended, "sqli") {
		t.Errorf("login has no params — mechanical fallback should not add sqli: %v", login.Recommended)
	}
	search := byKey["a.example|/search"]
	if search.Fallback {
		t.Errorf("search item should not be fallback: %+v", search)
	}
	if !has(search.Recommended, "sqli") {
		t.Errorf("search item should carry the LLM-recommended sqli: %v", search.Recommended)
	}
}

// 전체 폴백(무프로바이더·오류·파싱실패) 시에도 카드가 "AI 추천"처럼 보이면 안 된다 —
// Fallback 플래그가 항목마다 true 로 찍혀야 프론트가 폴백 배지를 올바르게 그린다.
func TestRecommendGlobalFallbackMarksEachItemFallback(t *testing.T) {
	llm.SetProvider(nil)
	res := Recommend(context.Background(), sampleTargets(), sampleCatalog())
	for _, it := range res.Items {
		if !it.Fallback {
			t.Errorf("item %s: Fallback=false, want true (전체 폴백인데 배지가 AI 추천으로 잘못 보임)", it.Key)
		}
		if it.Reason == "" {
			t.Errorf("item %s: Reason empty, want a fallback reason", it.Key)
		}
	}
}

// LLM이 reason을 같이 주면 파라미터 엔드포인트에는 그대로 실려야 한다.
// 파라미터 없는 엔드포인트는 LLM 배치에서 제외되므로(낭비 제거) LLM reason 대신
// 규칙 기반 reason 을 받는다 — mock 이 /login 에 reason 을 줘도 무시된다.
func TestRecommendCarriesPerItemReason(t *testing.T) {
	stub := &stubProvider{reply: `{"items":[
		{"key":"a.example|/login","detectors":["sec-headers"],"reason":"로그인 폼이라 인증 관련만"},
		{"key":"a.example|/search","detectors":["sqli"],"reason":"q 파라미터가 쿼리에 쓰일 가능성"}
	]}`}
	llm.SetProvider(stub)
	defer llm.SetProvider(nil)

	res := Recommend(context.Background(), sampleTargets(), sampleCatalog())
	byKey := map[string]Item{}
	for _, it := range res.Items {
		byKey[it.Key] = it
	}
	// /search 는 파라미터가 있어 LLM 대상 → LLM reason 이 그대로 실린다.
	if byKey["a.example|/search"].Reason != "q 파라미터가 쿼리에 쓰일 가능성" {
		t.Errorf("search reason=%q (LLM reason 이 실려야 함)", byKey["a.example|/search"].Reason)
	}
	// /login 은 파라미터가 없어 LLM 생략 → 규칙 기반 reason(LLM reason 무시).
	login := byKey["a.example|/login"]
	if !login.Fallback || login.Reason == "로그인 폼이라 인증 관련만" {
		t.Errorf("login(무파라미터)은 규칙 기반이어야 함: Fallback=%v reason=%q", login.Fallback, login.Reason)
	}
}

// ctx에 데드라인이 없으면 recommendTimeout 짜리 데드라인을 씌워 llm.Complete를 불러야 한다 —
// 이 배치 호출은 대상 전체를 한 번에 실어 보내 다른 LLM 호출보다 오래 걸릴 수 있다.
func TestRecommendAppliesLongerTimeoutWhenCtxHasNoDeadline(t *testing.T) {
	stub := &deadlineStub{reply: `{"items":[{"key":"a.example|/login","detectors":["sec-headers"]},{"key":"a.example|/search","detectors":["sqli"]}]}`}
	llm.SetProvider(stub)
	defer llm.SetProvider(nil)

	Recommend(context.Background(), sampleTargets(), sampleCatalog())
	if stub.deadline.IsZero() {
		t.Fatal("Complete()로 전달된 ctx에 데드라인이 없음 — recommendTimeout 이 적용 안 됨")
	}
	remain := time.Until(stub.deadline)
	if remain <= 0 || remain > recommendTimeout {
		t.Errorf("remaining=%v, want (0, %v]", remain, recommendTimeout)
	}
}

// 호출자가 이미 ctx에 데드라인을 걸어뒀으면(예: HTTP 요청 타임아웃) 그걸 존중하고 덮어쓰지 않는다.
func TestRecommendRespectsExistingDeadline(t *testing.T) {
	stub := &deadlineStub{reply: `{"items":[{"key":"a.example|/login","detectors":["sec-headers"]},{"key":"a.example|/search","detectors":["sqli"]}]}`}
	llm.SetProvider(stub)
	defer llm.SetProvider(nil)

	short := 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), short)
	defer cancel()
	Recommend(ctx, sampleTargets(), sampleCatalog())
	remain := time.Until(stub.deadline)
	if remain <= 0 || remain > short {
		t.Errorf("remaining=%v, want (0, %v] (기존 데드라인을 그대로 써야)", remain, short)
	}
}

type deadlineStub struct {
	reply    string
	deadline time.Time
}

func (p *deadlineStub) Name() string { return "deadline-stub" }
func (p *deadlineStub) Complete(ctx context.Context, _, _ string) (string, error) {
	p.deadline, _ = ctx.Deadline()
	return p.reply, nil
}

func richAllow() map[string]bool {
	return toSet([]string{
		"sec-headers", "http-method", "cookie-security", "reflected-input", "sqli", "sqli-blind", "dom-xss",
		"idor", "privesc", "sensitive-data", "csrf", "dir-indexing", "path-traversal", "open-redirect", "ssrf",
		"openssl-tls", "sslscan",
	})
}

// mechanicalRecommend 규칙 하나하나가 실제로 그렇게 동작하는지 — recommendSys 프롬프트의
// 규칙표를 코드로도 똑같이 계산한다(#59 이후 품질 개선: LLM 이 규칙을 놓쳐도 최소 보장).
func TestMechanicalRecommend(t *testing.T) {
	allow := richAllow()

	t.Run("static asset gets only baseline", func(t *testing.T) {
		got := mechanicalRecommend(endpoints.Target{Host: "a", Path: "/assets/logo.png", Methods: []string{"GET"}}, allow, false)
		if !has(got, "sec-headers") {
			t.Errorf("want baseline sec-headers: %v", got)
		}
		if has(got, "sqli") || has(got, "reflected-input") {
			t.Errorf("static asset should not get injection detectors: %v", got)
		}
	})

	t.Run("admin label adds idor/privesc", func(t *testing.T) {
		got := mechanicalRecommend(endpoints.Target{Host: "a", Path: "/admin", Methods: []string{"GET"}, Labels: []string{"admin"}}, allow, false)
		if !has(got, "idor") || !has(got, "privesc") {
			t.Errorf("admin label should add idor/privesc: %v", got)
		}
	})

	t.Run("state-changing method adds csrf, GET does not", func(t *testing.T) {
		if got := mechanicalRecommend(endpoints.Target{Host: "a", Path: "/save", Methods: []string{"POST"}}, allow, false); !has(got, "csrf") {
			t.Errorf("POST should add csrf: %v", got)
		}
		if got := mechanicalRecommend(endpoints.Target{Host: "a", Path: "/save", Methods: []string{"GET"}}, allow, false); has(got, "csrf") {
			t.Errorf("GET should not add csrf: %v", got)
		}
	})

	t.Run("file-like param adds path-traversal", func(t *testing.T) {
		t2 := endpoints.Target{Host: "a", Path: "/download", Methods: []string{"GET"}, Params: []endpoints.Param{{Name: "filename", In: "query"}}}
		if got := mechanicalRecommend(t2, allow, false); !has(got, "path-traversal") {
			t.Errorf("filename param should add path-traversal: %v", got)
		}
	})

	t.Run("url-like param adds open-redirect/ssrf", func(t *testing.T) {
		t2 := endpoints.Target{Host: "a", Path: "/go", Methods: []string{"GET"}, Params: []endpoints.Param{{Name: "redirect", In: "query"}}}
		got := mechanicalRecommend(t2, allow, false)
		if !has(got, "open-redirect") || !has(got, "ssrf") {
			t.Errorf("redirect param should add open-redirect/ssrf: %v", got)
		}
	})

	t.Run("includeTLS gates openssl-tls/sslscan", func(t *testing.T) {
		ep := endpoints.Target{Host: "a", Path: "/", Methods: []string{"GET"}}
		if got := mechanicalRecommend(ep, allow, false); has(got, "openssl-tls") {
			t.Errorf("includeTLS=false should not add openssl-tls: %v", got)
		}
		if got := mechanicalRecommend(ep, allow, true); !has(got, "openssl-tls") || !has(got, "sslscan") {
			t.Errorf("includeTLS=true should add openssl-tls/sslscan: %v", got)
		}
	})

	t.Run("auth-required adds idor/privesc/sensitive-data", func(t *testing.T) {
		ep := endpoints.Target{Host: "a", Path: "/me", Methods: []string{"GET"}, Auth: true}
		got := mechanicalRecommend(ep, allow, false)
		if !has(got, "idor") || !has(got, "privesc") || !has(got, "sensitive-data") {
			t.Errorf("auth-required should add idor/privesc/sensitive-data: %v", got)
		}
	})

	t.Run("directory-like path adds dir-indexing", func(t *testing.T) {
		ep := endpoints.Target{Host: "a", Path: "/uploads/", Methods: []string{"GET"}}
		if got := mechanicalRecommend(ep, allow, false); !has(got, "dir-indexing") {
			t.Errorf("directory-like path should add dir-indexing: %v", got)
		}
	})
}

// LLM이 파라미터 있는 엔드포인트를 잘못 분류해도(실측 사례: 정적 자산으로 오분류) 결정론적
// mechanical 레이어가 최소한을 채워 넣어야 한다 — union이지 LLM 응답을 그대로 신뢰하지 않는다.
func TestRecommendMechanicalFillsGapsWhenLLMUnderRecommends(t *testing.T) {
	stub := &stubProvider{reply: `{"items":[
		{"key":"a.example|/login","detectors":[]},
		{"key":"a.example|/search","detectors":[],"reason":"이 모델은 실수로 정적 자산이라고 답했다"}
	]}`}
	llm.SetProvider(stub)
	defer llm.SetProvider(nil)

	res := Recommend(context.Background(), sampleTargets(), sampleCatalog())
	byKey := map[string]Item{}
	for _, it := range res.Items {
		byKey[it.Key] = it
	}
	search := byKey["a.example|/search"]
	if !has(search.Recommended, "sqli") || !has(search.Recommended, "reflected-input") {
		t.Errorf("search has a query param — mechanical layer should add sqli/reflected-input even though LLM returned none: %v", search.Recommended)
	}
}

// openssl-tls/sslscan 은 호스트당 딱 하나의 엔드포인트에만 실려야 한다(호스트 전체 설정 점검이라
// 엔드포인트마다 반복하면 스캔만 느려진다).
func TestRecommendIncludesTLSOnlyOncePerHost(t *testing.T) {
	targets := []endpoints.Target{
		{Host: "a.example", Path: "/one", Methods: []string{"GET"}},
		{Host: "a.example", Path: "/two", Methods: []string{"GET"}},
		{Host: "b.example", Path: "/three", Methods: []string{"GET"}},
	}
	catalog := []detector.Info{{ID: "sec-headers", Name: "x"}, {ID: "openssl-tls", Name: "y"}, {ID: "sslscan", Name: "z"}}
	llm.SetProvider(nil)
	res := Recommend(context.Background(), targets, catalog)

	tlsCount := map[string]int{}
	for _, it := range res.Items {
		if has(it.Recommended, "openssl-tls") {
			tlsCount[it.Host]++
		}
	}
	if tlsCount["a.example"] != 1 {
		t.Errorf("a.example TLS-carrying items=%d, want 1", tlsCount["a.example"])
	}
	if tlsCount["b.example"] != 1 {
		t.Errorf("b.example TLS-carrying items=%d, want 1", tlsCount["b.example"])
	}
}

func TestRecommendNoTargets(t *testing.T) {
	stub := &stubProvider{reply: `{"items":[]}`}
	llm.SetProvider(stub)
	defer llm.SetProvider(nil)

	res := Recommend(context.Background(), nil, sampleCatalog())
	if len(res.Items) != 0 {
		t.Fatalf("Items=%d, want 0", len(res.Items))
	}
	if stub.calls != 0 {
		t.Errorf("calls=%d, want 0 (no targets → no LLM call)", stub.calls)
	}
}
