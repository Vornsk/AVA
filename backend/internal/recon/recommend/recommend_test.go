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

func TestRecommendNoProviderFallsBackToFullCatalog(t *testing.T) {
	llm.SetProvider(nil)
	res := Recommend(context.Background(), sampleTargets(), sampleCatalog())
	if res.Source != "fallback" || !res.Degraded {
		t.Fatalf("Source=%q Degraded=%v, want fallback/true", res.Source, res.Degraded)
	}
	if len(res.Items) != 2 {
		t.Fatalf("Items=%d, want 2", len(res.Items))
	}
	for _, it := range res.Items {
		if !has(it.Recommended, "sqli") || !has(it.Recommended, "reflected-input") || !has(it.Recommended, "sec-headers") {
			t.Errorf("Item %s missing non-destructive ids: %v", it.Key, it.Recommended)
		}
		if has(it.Recommended, "file-upload") {
			t.Errorf("Item %s includes destructive id in fallback: %v", it.Key, it.Recommended)
		}
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
	if !has(login.Recommended, "sec-headers") || !has(login.Recommended, "sqli") {
		t.Errorf("fallback item should get full non-destructive catalog: %v", login.Recommended)
	}
	search := byKey["a.example|/search"]
	if search.Fallback {
		t.Errorf("search item should not be fallback: %+v", search)
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

// LLM이 reason을 같이 주면 항목에 그대로 실려야 한다.
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
	if byKey["a.example|/login"].Reason != "로그인 폼이라 인증 관련만" {
		t.Errorf("login reason=%q", byKey["a.example|/login"].Reason)
	}
	if byKey["a.example|/search"].Reason != "q 파라미터가 쿼리에 쓰일 가능성" {
		t.Errorf("search reason=%q", byKey["a.example|/search"].Reason)
	}
}

// ctx에 데드라인이 없으면 recommendTimeout(180초)짜리 데드라인을 씌워 llm.Complete를 불러야 한다 —
// 이 배치 호출은 대상 전체를 한 번에 실어 보내 llm 패키지 기본(60초)보다 오래 걸릴 수 있다.
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
