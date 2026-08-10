package advisor

import (
	"testing"

	"proxypoc/internal/llm"
)

func dec(id int, method, path string, allow bool, conf float64) llm.Decision {
	return llm.Decision{
		ID:      id,
		Input:   llm.JudgeInput{Method: method, Path: path, ContentType: "application/json"},
		Verdict: llm.Verdict{Allow: allow, Confidence: conf, Model: "llama3.2"},
	}
}

// 동일 시그니처가 반복되고 일관되면 이관 후보로 도출돼야 한다(FR-6.2).
func TestConsistentPatternPromoted(t *testing.T) {
	decisions := []llm.Decision{
		dec(1, "POST", "/admin/delete", false, 0.9),
		dec(2, "POST", "/admin/delete", false, 0.95),
		dec(3, "POST", "/admin/delete", false, 0.9),
		// 다른 시그니처 1건 → 빈도 미달로 제외
		dec(4, "GET", "/health", true, 0.8),
	}
	cands := Analyze(decisions, 2, 0.7)
	if len(cands) != 1 {
		t.Fatalf("후보 %d개, want 1", len(cands))
	}
	c := cands[0]
	if c.Verdict != "block" || c.Hits != 3 || c.Consistency != 1.0 {
		t.Errorf("후보 = %+v, want block/3/1.0", c)
	}
	if c.DraftRule.Action != "block" || c.DraftRule.PathPattern == "" {
		t.Errorf("초안룰 부실: %+v", c.DraftRule)
	}
	if c.EstSavings != 3 || c.Status != "제안" {
		t.Errorf("절감/상태 오류: savings=%d status=%s", c.EstSavings, c.Status)
	}
}

// 일관성 낮으면(판정 갈림) 제외 + 경고(FR-6.2/6.3).
func TestInconsistentExcludedOrWarned(t *testing.T) {
	// 3 block + 2 allow → 일관성 60% < 70% → 제외
	decisions := []llm.Decision{
		dec(1, "POST", "/x", false, 0.9), dec(2, "POST", "/x", false, 0.9),
		dec(3, "POST", "/x", false, 0.9), dec(4, "POST", "/x", true, 0.9), dec(5, "POST", "/x", true, 0.9),
	}
	if got := len(Analyze(decisions, 2, 0.7)); got != 0 {
		t.Errorf("일관성 60%%는 제외돼야 함, got %d", got)
	}
	// 임계 낮추면 후보로 나오되 경고 포함.
	cands := Analyze(decisions, 2, 0.5)
	if len(cands) != 1 || cands[0].Warning == "" {
		t.Errorf("낮은 임계: 후보+경고 기대, got %+v", cands)
	}
}
