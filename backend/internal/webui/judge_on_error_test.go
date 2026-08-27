package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxypoc/internal/llm"
	"proxypoc/internal/project"
	"proxypoc/internal/user"
)

// 이슈 #56·#62 — 판단 불능 시 정책(fail-open/closed) API + 프로젝트 영속화.

func postJudgeOnError(t *testing.T, body string, role user.Role) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	judgeOnErrorHandler(w, asUser(http.MethodPost, "/api/judge-on-error", body, role))
	return w
}

func TestJudgeOnErrorGet(t *testing.T) {
	llm.ResetHealth() // 기본 allow 로 리셋
	w := httptest.NewRecorder()
	judgeOnErrorHandler(w, asUser(http.MethodGet, "/api/judge-on-error", "", user.RoleAnalyst))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200", w.Code)
	}
	var out llm.Health
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Policy != llm.FailOpen {
		t.Errorf("기본 policy=%q, want allow", out.Policy)
	}
}

func TestJudgeOnErrorPostRequiresLeader(t *testing.T) {
	llm.ResetHealth()
	if w := postJudgeOnError(t, `{"policy":"block"}`, user.RoleAnalyst); w.Code != http.StatusForbidden {
		t.Fatalf("수행원 code=%d, want 403", w.Code)
	}
	if llm.FailurePolicy() != llm.FailOpen {
		t.Errorf("권한 없는 요청이 정책을 바꿨다: %q", llm.FailurePolicy())
	}
}

func TestJudgeOnErrorPostPersistsOnActiveProject(t *testing.T) {
	project.Reset()
	llm.ResetHealth()
	p := project.Create(project.Project{Name: "prod"}) // 첫 생성 = 활성

	if w := postJudgeOnError(t, `{"policy":"block"}`, user.RoleLeader); w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200: %s", w.Code, w.Body.String())
	}
	if llm.FailurePolicy() != llm.FailClosed {
		t.Errorf("활성 정책 = %q, want block", llm.FailurePolicy())
	}
	got, _ := project.Get(p.ID)
	if got.JudgeOnError != llm.FailClosed {
		t.Errorf("프로젝트에 영속화되지 않음: %q", got.JudgeOnError)
	}

	// 잘못된 값은 400 이고 정책은 그대로여야 한다 (조용한 폴백 금지)
	w := postJudgeOnError(t, `{"policy":"paranoid"}`, user.RoleLeader)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("잘못된 값 code=%d, want 400", w.Code)
	}
	if llm.FailurePolicy() != llm.FailClosed {
		t.Errorf("거절된 요청이 정책을 바꿨다: %q", llm.FailurePolicy())
	}
}

// 프로젝트를 전환하면 그 프로젝트의 판단 불능 정책이 따라 붙어야 한다 (#56 핵심,
// ApplyActiveProjectSettings 경로 — 앞 프로젝트의 block 이 남아 다음 진단을 조용히 막지 않아야).
func TestActivateProjectSwitchesJudgeOnError(t *testing.T) {
	project.Reset()
	llm.ResetHealth()
	prod := project.Create(project.Project{Name: "prod", JudgeOnError: llm.FailClosed})
	plain := project.Create(project.Project{Name: "plain"}) // 미지정 → 기본 allow

	activate := func(id string) {
		t.Helper()
		w := httptest.NewRecorder()
		activateHandler(w, asUser(http.MethodPost, "/api/activate-project", `{"id":"`+id+`"}`, user.RoleLeader))
		if w.Code != http.StatusOK {
			t.Fatalf("activate %s code=%d: %s", id, w.Code, w.Body.String())
		}
	}

	activate(prod.ID)
	if got := llm.FailurePolicy(); got != llm.FailClosed {
		t.Errorf("prod 활성화 후 정책 = %q, want block", got)
	}
	activate(plain.ID)
	if got := llm.FailurePolicy(); got != llm.FailOpen {
		t.Errorf("미지정 프로젝트 활성화 후 정책 = %q, want 기본(allow)", got)
	}
}
