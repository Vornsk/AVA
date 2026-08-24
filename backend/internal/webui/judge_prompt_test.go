package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxypoc/internal/llm"
	"proxypoc/internal/project"
	"proxypoc/internal/user"
)

// 이슈 #53 — 판단 프롬프트 정책 API + 프로젝트 전환 시 정책 적용.

func asUser(method, target, body string, role user.Role) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	return r.WithContext(context.WithValue(r.Context(), userKey, user.User{ID: "u-1", Name: "t", Role: role}))
}

func postJudgePrompt(t *testing.T, body string, role user.Role) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	judgePromptHandler(w, asUser(http.MethodPost, "/api/judge-prompt", body, role))
	return w
}

func TestJudgePromptGet(t *testing.T) {
	llm.SetBasePolicy(llm.BasePolicy()) // 활성=기본 으로 리셋
	w := httptest.NewRecorder()
	judgePromptHandler(w, asUser(http.MethodGet, "/api/judge-prompt", "", user.RoleAnalyst))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200", w.Code)
	}
	var out struct {
		Active       llm.Policy   `json:"active"`
		Base         llm.Policy   `json:"base"`
		Presets      []llm.Policy `json:"presets"`
		MaxCustomLen int          `json:"max_custom_len"`
	}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Presets) != 3 {
		t.Errorf("프리셋 %d개, want 3", len(out.Presets))
	}
	if out.Active.ID == "" || out.Active.Hash == "" || out.Base.ID == "" {
		t.Errorf("정책 식별자 누락: %+v", out)
	}
	if out.MaxCustomLen != llm.MaxCustomLen {
		t.Errorf("max_custom_len=%d", out.MaxCustomLen)
	}
}

func TestJudgePromptPostRequiresLeader(t *testing.T) {
	before := llm.JudgePolicy()
	if w := postJudgePrompt(t, `{"preset":"permissive"}`, user.RoleAnalyst); w.Code != http.StatusForbidden {
		t.Fatalf("수행원 code=%d, want 403", w.Code)
	}
	if llm.JudgePolicy().Hash != before.Hash {
		t.Error("권한 없는 요청이 정책을 바꿨다")
	}
}

func TestJudgePromptPostPersistsOnActiveProject(t *testing.T) {
	project.Reset()
	llm.SetBasePolicy(mustPolicy(t, llm.PresetBalanced))
	p := project.Create(project.Project{Name: "prod"}) // 첫 생성 = 활성

	if w := postJudgePrompt(t, `{"preset":"strict"}`, user.RoleLeader); w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200: %s", w.Code, w.Body.String())
	}
	if got := llm.JudgePolicy().ID; got != llm.PresetStrict {
		t.Errorf("활성 정책 = %q, want strict", got)
	}
	got, _ := project.Get(p.ID)
	if got.JudgePrompt != "strict" {
		t.Errorf("프로젝트에 영속화되지 않음: %q", got.JudgePrompt)
	}

	// 잘못된 프리셋은 400 이고 정책은 그대로여야 한다 (조용한 폴백 금지)
	w := postJudgePrompt(t, `{"preset":"paranoid"}`, user.RoleLeader)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("잘못된 프리셋 code=%d, want 400", w.Code)
	}
	if llm.JudgePolicy().ID != llm.PresetStrict {
		t.Errorf("거절된 요청이 정책을 바꿨다: %q", llm.JudgePolicy().ID)
	}

	// 커스텀 → id=custom, 프로젝트에도 원문이 남는다
	if w := postJudgePrompt(t, `{"custom":"Block anything touching /vault."}`, user.RoleLeader); w.Code != http.StatusOK {
		t.Fatalf("커스텀 code=%d: %s", w.Code, w.Body.String())
	}
	if llm.JudgePolicy().ID != "custom" {
		t.Errorf("활성 정책 = %q, want custom", llm.JudgePolicy().ID)
	}
	got, _ = project.Get(p.ID)
	if got.JudgePromptCustom == "" {
		t.Error("커스텀 원문이 프로젝트에 저장되지 않음")
	}
}

// 프로젝트를 전환하면 그 프로젝트의 판단 정책이 따라 붙어야 한다 (이슈 #53 핵심).
func TestActivateProjectSwitchesJudgePolicy(t *testing.T) {
	project.Reset()
	llm.SetBasePolicy(mustPolicy(t, llm.PresetBalanced))
	prod := project.Create(project.Project{Name: "prod", JudgePrompt: "strict"})
	stg := project.Create(project.Project{Name: "stg", JudgePrompt: "permissive"})
	plain := project.Create(project.Project{Name: "plain"}) // 미지정 → 기본 정책

	activate := func(id string) {
		t.Helper()
		w := httptest.NewRecorder()
		activateHandler(w, asUser(http.MethodPost, "/api/activate-project", `{"id":"`+id+`"}`, user.RoleLeader))
		if w.Code != http.StatusOK {
			t.Fatalf("activate %s code=%d: %s", id, w.Code, w.Body.String())
		}
	}

	activate(prod.ID)
	if got := llm.JudgePolicy().ID; got != llm.PresetStrict {
		t.Errorf("prod 활성화 후 정책 = %q, want strict", got)
	}
	activate(stg.ID)
	if got := llm.JudgePolicy().ID; got != llm.PresetPermissive {
		t.Errorf("stg 활성화 후 정책 = %q, want permissive", got)
	}
	activate(plain.ID)
	if got := llm.JudgePolicy().ID; got != llm.PresetBalanced {
		t.Errorf("미지정 프로젝트 활성화 후 정책 = %q, want 기본(balanced)", got)
	}
}

func mustPolicy(t *testing.T, preset string) llm.Policy {
	t.Helper()
	p, err := llm.ResolvePolicy(preset, "")
	if err != nil {
		t.Fatalf("ResolvePolicy(%q): %v", preset, err)
	}
	return p
}
