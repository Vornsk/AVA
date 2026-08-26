package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/user"
)

func TestEndpointsClearHandlerRequiresLeader(t *testing.T) {
	endpoints.Reset()
	endpoints.Record("http", "ch:80", "GET", "/x", nil, false, "")

	w := httptest.NewRecorder()
	endpointsClearHandler(w, asUser(http.MethodPost, "/api/endpoints/clear", "", user.RoleAnalyst))
	if w.Code != http.StatusForbidden {
		t.Fatalf("analyst code=%d, want 403", w.Code)
	}
	if len(endpoints.Targets()) != 1 {
		t.Error("거부된 요청이 데이터를 지웠다")
	}
}

func TestEndpointsClearHandlerClearsAll(t *testing.T) {
	endpoints.Reset()
	endpoints.Record("http", "ch:80", "GET", "/x", nil, false, "")
	endpoints.Record("http", "ch:80", "POST", "/y", nil, false, "")

	w := httptest.NewRecorder()
	endpointsClearHandler(w, asUser(http.MethodPost, "/api/endpoints/clear", "", user.RoleLeader))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200: %s", w.Code, w.Body.String())
	}
	if len(endpoints.Targets()) != 0 {
		t.Error("초기화 후에도 대상이 남아있음")
	}
}

func TestEndpointDeleteHandler(t *testing.T) {
	endpoints.Reset()
	endpoints.Record("http", "dh:80", "GET", "/keep", nil, false, "")
	endpoints.Record("http", "dh:80", "GET", "/drop", nil, false, "")

	w := httptest.NewRecorder()
	endpointDeleteHandler(w, asUser(http.MethodPost, "/api/endpoints/delete", `{"host":"dh:80","path":"/drop"}`, user.RoleLeader))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200: %s", w.Code, w.Body.String())
	}
	if _, ok := endpoints.Find("dh:80", "/drop"); ok {
		t.Error("삭제한 노드가 여전히 조회됨")
	}
	if _, ok := endpoints.Find("dh:80", "/keep"); !ok {
		t.Error("무관한 노드까지 지워짐")
	}
}

func TestEndpointDeleteHandlerNotFound(t *testing.T) {
	endpoints.Reset()
	endpoints.Record("http", "dh2:80", "GET", "/only", nil, false, "")

	w := httptest.NewRecorder()
	endpointDeleteHandler(w, asUser(http.MethodPost, "/api/endpoints/delete", `{"host":"dh2:80","path":"/nope"}`, user.RoleLeader))
	if w.Code != http.StatusNotFound {
		t.Fatalf("code=%d, want 404", w.Code)
	}
}

// TestEndpointDeleteHandlerRootPreservesSiblings — 실서비스에서 실제로 겪은 회귀 재현:
// "/"(호스트 루트) 자체가 엔드포인트로 캡처된 상태에서 그것만 삭제해도 같은 호스트의
// 다른 엔드포인트(크롤로 발견된 나머지 전부)가 함께 사라지면 안 된다.
func TestEndpointDeleteHandlerRootPreservesSiblings(t *testing.T) {
	endpoints.Reset()
	endpoints.Record("http", "rh:80", "GET", "/", nil, false, "")
	endpoints.Record("http", "rh:80", "GET", "/m_login.php", nil, false, "")
	endpoints.Record("http", "rh:80", "POST", "/m_board.php", nil, false, "")

	w := httptest.NewRecorder()
	endpointDeleteHandler(w, asUser(http.MethodPost, "/api/endpoints/delete", `{"host":"rh:80","path":"/"}`, user.RoleLeader))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200: %s", w.Code, w.Body.String())
	}

	targets := endpoints.Targets()
	if len(targets) != 2 {
		t.Fatalf("Targets()=%d, want 2 (m_login.php, m_board.php 만 남아야) — got %+v", len(targets), targets)
	}
	for _, tg := range targets {
		if tg.Path == "/" {
			t.Error("삭제한 루트 엔드포인트가 여전히 Targets()에 남아있음")
		}
	}
}

func TestEndpointDeleteHandlerRequiresLeader(t *testing.T) {
	endpoints.Reset()
	endpoints.Record("http", "dh3:80", "GET", "/x", nil, false, "")

	w := httptest.NewRecorder()
	endpointDeleteHandler(w, asUser(http.MethodPost, "/api/endpoints/delete", `{"host":"dh3:80","path":"/x"}`, user.RoleAnalyst))
	if w.Code != http.StatusForbidden {
		t.Fatalf("analyst code=%d, want 403", w.Code)
	}
	if _, ok := endpoints.Find("dh3:80", "/x"); !ok {
		t.Error("거부된 요청이 데이터를 지웠다")
	}
}
