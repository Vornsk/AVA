package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxypoc/internal/project"
	"proxypoc/internal/user"
)

// 프로젝트 생성 시 스코프 URL 정규화 + main_url 이중 스킴 방지.
// 사용자가 스코프 칸에 "http://192.168.100.5/" 를 넣어도 크롤이 되도록.
func TestProjectCreateNormalizesScope(t *testing.T) {
	project.Reset()
	body := `{"name":"mall","scope":["http://192.168.100.5/"]}`
	r := httptest.NewRequest(http.MethodPost, "/api/projects", strings.NewReader(body)).
		WithContext(context.WithValue(context.Background(), userKey, user.User{ID: "u-1", Name: "t", Role: user.RoleLeader}))
	w := httptest.NewRecorder()
	projectsHandler(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d: %s", w.Code, w.Body.String())
	}
	var p project.Project
	if err := json.NewDecoder(w.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	if len(p.Scope) != 1 || p.Scope[0] != "192.168.100.5" {
		t.Errorf("scope = %v, want [192.168.100.5] (호스트만)", p.Scope)
	}
	// main_url 은 이중 스킴이 아니어야 한다 (예전엔 https://http://... 가 됐다)
	if strings.Count(p.MainURL, "://") != 1 {
		t.Errorf("main_url = %q, want 단일 스킴", p.MainURL)
	}
	if p.MainURL != "https://192.168.100.5" {
		t.Errorf("main_url = %q, want https://192.168.100.5", p.MainURL)
	}
}

// 사용자가 main_url 을 직접 주면 존중하되 스킴 없으면 붙인다.
func TestProjectCreateMainURLProvided(t *testing.T) {
	project.Reset()
	body := `{"name":"m2","scope":["192.168.100.5"],"main_url":"http://192.168.100.5:8080"}`
	r := httptest.NewRequest(http.MethodPost, "/api/projects", strings.NewReader(body)).
		WithContext(context.WithValue(context.Background(), userKey, user.User{ID: "u-1", Name: "t", Role: user.RoleLeader}))
	w := httptest.NewRecorder()
	projectsHandler(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d", w.Code)
	}
	var p project.Project
	json.NewDecoder(w.Body).Decode(&p)
	if p.MainURL != "http://192.168.100.5:8080" {
		t.Errorf("main_url = %q, want 사용자 입력 그대로", p.MainURL)
	}
}
