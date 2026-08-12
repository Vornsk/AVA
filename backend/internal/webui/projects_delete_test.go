package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxypoc/internal/finding"
	"proxypoc/internal/project"
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
	a := project.Create(project.Project{Name: "keep"}) // 활성
	b := project.Create(project.Project{Name: "trash-me"})
	finding.Add(finding.Finding{ProjectID: b.ID, Vuln: "x"}) // b 소속 finding 시딩

	// 활성 프로젝트(a) 삭제 → 409
	w := httptest.NewRecorder()
	projectDeleteHandler(w, leaderReq("POST", "/api/projects/"+a.ID+"/delete", a.ID))
	if w.Code != http.StatusConflict {
		t.Fatalf("활성 삭제 code=%d, want 409", w.Code)
	}

	// b 소프트 삭제 → 200, 휴지통 이동, finding 은 보존
	w = httptest.NewRecorder()
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
