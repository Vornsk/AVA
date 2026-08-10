package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Ollama 프로바이더의 HTTP 요청 포맷·응답 파싱을 가짜 서버로 검증 (실제 LLM 없이).
func TestOllamaProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		// Ollama chat 응답: message.content = verdict JSON
		w.Write([]byte(`{"message":{"content":"{\"allow\":false,\"reason\":\"risky\",\"confidence\":0.9}"}}`))
	}))
	defer srv.Close()

	SetProvider(NewOllama("test-model", srv.URL))
	v := Judge(context.Background(), JudgeInput{Method: "POST", Path: "/ollamatest"})
	if v.Allow {
		t.Error("verdict should be block (allow=false)")
	}
	if v.Reason != "risky" {
		t.Errorf("reason = %q, want 'risky'", v.Reason)
	}
	if v.Provider != "ollama" {
		t.Errorf("provider = %q", v.Provider)
	}
}

func TestMockJudge(t *testing.T) {
	SetProvider(MockProvider{})
	if v := Judge(context.Background(), JudgeInput{Method: "POST", Path: "/mA", ParamKeys: []string{"amount"}}); v.Allow {
		t.Error("financial param (amount) should be blocked")
	}
	if v := Judge(context.Background(), JudgeInput{Method: "POST", Path: "/mB", ParamKeys: []string{"comment"}}); !v.Allow {
		t.Error("benign param (comment) should be allowed")
	}
}

func TestMockReview(t *testing.T) {
	SetProvider(MockProvider{})
	rr := Review(context.Background(), ReviewInput{Vuln: "민감정보 노출", Severity: "high", Evidence: "주민등록번호 발견"})
	if rr.Verdict != "real" {
		t.Errorf("verdict = %q, want real (sensitive evidence)", rr.Verdict)
	}
	if rr.Remediation == "" {
		t.Error("remediation should be generated")
	}
	if rr.Provider != "mock" {
		t.Errorf("provider = %q", rr.Provider)
	}
}

// OpenAI 호환 프로바이더의 요청·응답 파싱을 가짜 서버로 검증.
func TestOpenAIProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer k-123" {
			t.Errorf("missing/wrong bearer: %q", r.Header.Get("Authorization"))
		}
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"allow\":true,\"reason\":\"ok\",\"confidence\":0.7}"}}]}`))
	}))
	defer srv.Close()

	SetProvider(NewOpenAI("k-123", "gpt-test", srv.URL))
	v := Judge(context.Background(), JudgeInput{Method: "GET", Path: "/openaitest"})
	if !v.Allow || v.Reason != "ok" || v.Provider != "openai" {
		t.Errorf("verdict = %+v", v)
	}
}

func TestNewFactory(t *testing.T) {
	if New("mock", "", "", "").Name() != "mock" {
		t.Error("mock")
	}
	if New("ollama", "", "", "").Name() != "ollama" {
		t.Error("ollama")
	}
	if New("openai", "", "", "").Name() != "openai" {
		t.Error("openai")
	}
	if New("anthropic", "", "", "").Name() != "anthropic" {
		t.Error("anthropic")
	}
	if New("unknown-xyz", "", "", "").Name() != "mock" {
		t.Error("unknown → mock fallback")
	}
}

func TestJudgeCacheAndDecisions(t *testing.T) {
	SetProvider(MockProvider{})
	in := JudgeInput{Method: "POST", Path: "/x", ParamKeys: []string{"amount"}}

	before := len(Decisions())
	Judge(context.Background(), in) // miss
	Judge(context.Background(), in) // hit (cache)
	ds := Decisions()

	if len(ds) != before+2 {
		t.Fatalf("expected 2 new decisions, got %d", len(ds)-before)
	}
	if ds[len(ds)-2].Cached {
		t.Error("first Judge should NOT be cached")
	}
	if !ds[len(ds)-1].Cached {
		t.Error("second identical Judge SHOULD be cached")
	}
}

func TestJudgeNoProviderFailsOpen(t *testing.T) {
	SetProvider(nil)
	v := Judge(context.Background(), JudgeInput{Method: "POST", Path: "/noprov", ParamKeys: []string{"amount"}})
	if !v.Allow {
		t.Error("no provider should fail-open (allow) for availability")
	}
	SetProvider(MockProvider{}) // 복원
}
