package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/llm"
	"proxypoc/internal/recon/recommend"
	"proxypoc/internal/scanengine"
	"proxypoc/internal/user"
)

func TestScanRecommendHandlerNoTargets(t *testing.T) {
	endpoints.Reset()
	w := httptest.NewRecorder()
	scanRecommendHandler(w, asUser(http.MethodPost, "/api/scan/recommend", "", user.RoleLeader))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code=%d, want 400", w.Code)
	}
}

func TestScanRecommendHandlerMethodNotAllowed(t *testing.T) {
	w := httptest.NewRecorder()
	scanRecommendHandler(w, asUser(http.MethodGet, "/api/scan/recommend", "", user.RoleLeader))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d, want 405", w.Code)
	}
}

func TestScanRecommendHandlerHappyPath(t *testing.T) {
	endpoints.Reset()
	llm.SetProvider(nil) // 결정론적 폴백 경로(플레이키니스 방지)
	endpoints.Record("http", "rh:80", "GET", "/rec-path", []endpoints.Param{{Name: "q", In: "query"}}, false, "")

	w := httptest.NewRecorder()
	scanRecommendHandler(w, asUser(http.MethodPost, "/api/scan/recommend", "", user.RoleLeader))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200: %s", w.Code, w.Body.String())
	}
	var res recommend.Result
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(res.Items) != 1 {
		t.Fatalf("Items=%d, want 1", len(res.Items))
	}
	want := "rh:80|/rec-path"
	if res.Items[0].Key != want {
		t.Errorf("Key=%q, want %q", res.Items[0].Key, want)
	}
	if res.Source != "fallback" || !res.Degraded {
		t.Errorf("Source=%q Degraded=%v, want fallback/true (no provider)", res.Source, res.Degraded)
	}
}

// per_target 이 /api/scan 까지 전달돼 scanengine.Start 의 Total 계산에 반영돼야 한다(690 문제 해소 확인).
func TestScanHandlerPerTargetPassthrough(t *testing.T) {
	endpoints.Reset()
	scanengine.SetSafeMode(false)
	endpoints.Record("http", "ph:80", "GET", "/p1", nil, false, "")
	endpoints.Record("http", "ph:80", "GET", "/p2", nil, false, "")

	body := `{"detectors":["sec-headers","sensitive-data"],"per_target":{"ph:80|/p1":["sec-headers"]}}`
	w := httptest.NewRecorder()
	scanHandler(w, asUser(http.MethodPost, "/api/scan", body, user.RoleLeader))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200: %s", w.Code, w.Body.String())
	}
	var sr scanengine.ScanRun
	if err := json.NewDecoder(w.Body).Decode(&sr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// p1: override로 1개, p2: override 없음→detectors 전체(2개) = 합계 3.
	if sr.Total != 3 {
		t.Errorf("Total=%d, want 3 (1 override + 2 full-set)", sr.Total)
	}
}
