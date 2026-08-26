package webui

import (
	"testing"

	"proxypoc/internal/checklist"
	"proxypoc/internal/llm"
	"proxypoc/internal/project"
	"proxypoc/internal/scope"
)

// TestApplyActiveProjectSettingsConfiguresScope — 실서비스 회귀 재현: 서버 재시작 후
// 활성 프로젝트를 복원할 때 판단 프롬프트만 재적용되고 스코프는 그대로였던 버그.
// 이 함수(main.go 기동 경로와 activateHandler 가 공유)가 스코프까지 반영해야 한다.
func TestApplyActiveProjectSettingsConfiguresScope(t *testing.T) {
	scope.Configure([]string{"stale-example.com"}, nil, nil) // 재시작 직후처럼 "고정 기본값"이 걸려있다고 가정
	if allowed, _ := scope.Allowed("192.168.100.5", "/"); allowed {
		t.Fatal("사전조건 오류: 이미 허용돼 있음")
	}

	p := project.Project{ID: "p-x", Name: "target", Scope: []string{"192.168.100.5"}}
	if _, err := ApplyActiveProjectSettings(p); err != nil {
		t.Fatalf("ApplyActiveProjectSettings: %v", err)
	}

	if allowed, reason := scope.Allowed("192.168.100.5", "/"); !allowed {
		t.Errorf("활성 프로젝트 스코프가 반영 안 됨(reason=%q) — 크롤이 조용히 0건으로 끝나는 회귀", reason)
	}
	if allowed, _ := scope.Allowed("stale-example.com", "/"); allowed {
		t.Error("이전 스코프가 여전히 허용됨 — Configure 가 교체가 아니라 누적됨")
	}
}

// TestApplyActiveProjectSettingsAppliesSchemesAndPolicy — 스코프뿐 아니라 점검 스킴·판단
// 프롬프트 정책도 같이 반영되는지(activateHandler 가 하던 일 전부를 대체했는지) 확인.
func TestApplyActiveProjectSettingsAppliesSchemesAndPolicy(t *testing.T) {
	llm.SetBasePolicy(mustPolicy(t, llm.PresetBalanced))
	checklist.SetSelected(nil)

	p := project.Project{ID: "p-y", Name: "y", Scope: []string{"h.com"},
		Schemes: []string{string(checklist.SchemeFinance)}, JudgePrompt: "strict"}
	pol, err := ApplyActiveProjectSettings(p)
	if err != nil {
		t.Fatalf("ApplyActiveProjectSettings: %v", err)
	}
	if pol.ID != llm.PresetStrict {
		t.Errorf("판단 정책=%q, want strict", pol.ID)
	}
	if llm.JudgePolicy().ID != llm.PresetStrict {
		t.Errorf("전역 판단 정책이 반영 안 됨: %q", llm.JudgePolicy().ID)
	}
	sel := checklist.Selected()
	if len(sel) != 1 || sel[0] != checklist.SchemeFinance {
		t.Errorf("선택 스킴=%v, want [%s]", sel, checklist.SchemeFinance)
	}
}
