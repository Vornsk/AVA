package recommend

import (
	"context"
	"strings"
	"testing"

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
