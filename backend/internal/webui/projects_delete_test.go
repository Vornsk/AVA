package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxypoc/internal/finding"
	"proxypoc/internal/project"
	"proxypoc/internal/scope"
	"proxypoc/internal/user"
)

// 이슈 #14 — 프로젝트 소프트 삭제/복구/영구삭제 핸들러 + cascade.
func leaderReq(method, target, id string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.SetPathValue("id", id)
	return r.WithContext(context.WithValue(r.Context(), userKey, user.User{ID: "u-1", Name: "t", Role: user.RoleLeader}))
}

func TestProjectSoftDeleteHandlers(t *testing.T) {
	project.Reset()
	finding.Clear()
	_ = project.Create(project.Project{Name: "keep"}) // 활성(첫 생성) — b 삭제 시 자동 전환이 안 일어나게 상주
	b := project.Create(project.Project{Name: "trash-me"})
	finding.Add(finding.Finding{ProjectID: b.ID, Vuln: "x"}) // b 소속 finding 시딩

	// b(비활성) 소프트 삭제 → 200, 휴지통 이동, finding 은 보존
	w := httptest.NewRecorder()
	projectDeleteHandler(w, leaderReq("POST", "/api/projects/"+b.ID+"/delete", b.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("소프트삭제 code=%d, want 200", w.Code)
	}
	if len(project.Trash()) != 1 {
		t.Fatal("휴지통에 없음")
	}
	if len(finding.ByProject(b.ID)) != 1 {
		t.Fatal("소프트 삭제 중 finding 이 사라짐(보존해야 함)")
	}

	// 복구 → 200, 휴지통 비고 finding 유지
	w = httptest.NewRecorder()
	projectRestoreHandler(w, leaderReq("POST", "/api/projects/"+b.ID+"/restore", b.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("복구 code=%d, want 200", w.Code)
	}
	if len(project.Trash()) != 0 {
		t.Fatal("복구 후에도 휴지통에 남음")
	}

	// 휴지통 아닌데 purge 시도 → 409 (먼저 삭제 필요)
	w = httptest.NewRecorder()
	projectPurgeHandler(w, leaderReq("POST", "/api/projects/"+b.ID+"/purge", b.ID))
	if w.Code != http.StatusConflict {
		t.Fatalf("비휴지통 purge code=%d, want 409", w.Code)
	}

	// 삭제 후 영구삭제 → 200, cascade 로 finding 제거
	projectDeleteHandler(httptest.NewRecorder(), leaderReq("POST", "/api/projects/"+b.ID+"/delete", b.ID))
	w = httptest.NewRecorder()
	projectPurgeHandler(w, leaderReq("POST", "/api/projects/"+b.ID+"/purge", b.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("영구삭제 code=%d, want 200", w.Code)
	}
	if _, ok := project.Get(b.ID); ok {
		t.Fatal("영구삭제 후에도 프로젝트가 조회됨")
	}
	if len(finding.ByProject(b.ID)) != 0 {
		t.Fatal("cascade 실패: finding 이 안 지워짐")
	}
}

// 막다른 골목 개선 — 활성 프로젝트를 지우면 다른 살아있는 프로젝트로 자동 전환하고
// 그 프로젝트의 스코프가 프록시에 재적용된다("먼저 전환하세요" 수동 단계 제거).
func TestProjectDeleteActiveAutoSwitches(t *testing.T) {
	project.Reset()
	finding.Clear()
	scope.Configure(nil, nil, nil)
	a := project.Create(project.Project{Name: "a", Scope: []string{"a.example.com"}}) // 첫 생성 = 활성
	b := project.Create(project.Project{Name: "b", Scope: []string{"b.example.com"}})
	if ap, _ := project.Active(); ap.ID != a.ID {
		t.Fatalf("초기 활성=%q, want %q", ap.ID, a.ID)
	}

	// 활성(a) 삭제 → 200, b 로 자동 전환
	w := httptest.NewRecorder()
	projectDeleteHandler(w, leaderReq("POST", "/api/projects/"+a.ID+"/delete", a.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("활성 삭제 code=%d, want 200: %s", w.Code, w.Body.String())
	}
	if ap, ok := project.Active(); !ok || ap.ID != b.ID {
		t.Fatalf("자동 전환 실패: 활성=%+v, want %q", ap, b.ID)
	}
	// b 의 스코프가 프록시에 재적용됐는가 (지운 a 의 스코프가 남으면 안 됨)
	if hosts := scope.HostsSnapshot(); len(hosts) != 1 || hosts[0] != "b.example.com" {
		t.Errorf("삭제 후 스코프=%v, want [b.example.com]", hosts)
	}
}

// 막다른 골목 개선 — 마지막 남은 활성 프로젝트도 지울 수 있고, 그러면 활성 없음 상태가
// 되며 스코프가 안전하게 비워진다(지운 프로젝트의 스코프가 프록시에 남지 않는다).
func TestProjectDeleteLastActiveClearsScope(t *testing.T) {
	project.Reset()
	finding.Clear()
	scope.Configure(nil, nil, nil)
	a := project.Create(project.Project{Name: "only", Scope: []string{"only.example.com"}})
	// 활성 적용을 실제로 반영(핸들러가 삭제 시 비우는지 대조하기 위해 먼저 채워둔다)
	if _, err := ApplyActiveProjectSettings(a); err != nil {
		t.Fatalf("초기 적용 실패: %v", err)
	}
	if hosts := scope.HostsSnapshot(); len(hosts) != 1 {
		t.Fatalf("사전 스코프 세팅 실패: %v", hosts)
	}

	w := httptest.NewRecorder()
	projectDeleteHandler(w, leaderReq("POST", "/api/projects/"+a.ID+"/delete", a.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("마지막 프로젝트 삭제 code=%d, want 200: %s", w.Code, w.Body.String())
	}
	if ap, ok := project.Active(); ok {
		t.Fatalf("삭제 후에도 활성이 있음: %+v (want 활성 없음)", ap)
	}
	if hosts := scope.HostsSnapshot(); len(hosts) != 0 {
		t.Errorf("활성 없음인데 스코프가 남음: %v", hosts)
	}

	// 복구 → 활성이 없었으므로 자동 활성화되고 스코프가 다시 적용된다.
	w = httptest.NewRecorder()
	projectRestoreHandler(w, leaderReq("POST", "/api/projects/"+a.ID+"/restore", a.ID))
	if w.Code != http.StatusOK {
		t.Fatalf("복구 code=%d, want 200: %s", w.Code, w.Body.String())
	}
	if ap, ok := project.Active(); !ok || ap.ID != a.ID {
		t.Fatalf("복구 후 자동 활성화 안 됨: %v", ap)
	}
	if hosts := scope.HostsSnapshot(); len(hosts) != 1 || hosts[0] != "only.example.com" {
		t.Errorf("복구 자동 활성화 후 스코프=%v, want [only.example.com]", hosts)
	}
}
