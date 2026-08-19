package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxypoc/internal/endpoints"
)

// 이슈 #7 — 엔드포인트 조회 API(필터·페이징·상세) 동작 검증.

func seedEndpoints() {
	endpoints.Record("http", "h1:80", "GET", "/users/1", []endpoints.Param{{Name: "q", In: "query"}}, false, "")
	endpoints.Record("http", "h1:80", "POST", "/login", nil, true, "룰 허용: login")
	endpoints.Record("http", "h2:80", "GET", "/health", nil, false, "")
}

func listEndpoints(t *testing.T, query string) ([]endpoints.Target, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/endpoints?"+query, nil)
	w := httptest.NewRecorder()
	endpointsListHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200", w.Code)
	}
	var out []endpoints.Target
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out, w.Header().Get("X-Total-Count")
}

func TestEndpointsListFilter(t *testing.T) {
	seedEndpoints()

	all, total := listEndpoints(t, "")
	if len(all) < 3 || total == "" {
		t.Fatalf("무필터 전체 %d개(total=%q) — 최소 3 기대", len(all), total)
	}

	// method 필터
	posts, _ := listEndpoints(t, "method=POST")
	if len(posts) == 0 {
		t.Fatal("method=POST 결과 없음")
	}
	for _, tg := range posts {
		if !contains(tg.Methods, "POST") {
			t.Fatalf("method 필터 위반: %v", tg.Methods)
		}
	}

	// auth 필터
	authed, _ := listEndpoints(t, "auth=true")
	if len(authed) == 0 {
		t.Fatal("auth=true 결과 없음")
	}
	for _, tg := range authed {
		if !tg.Auth {
			t.Fatalf("auth 필터 위반: %+v", tg)
		}
	}

	// q 검색 (경로)
	login, _ := listEndpoints(t, "q=login")
	for _, tg := range login {
		if !strings.Contains(strings.ToLower(tg.Host+tg.Path), "login") {
			t.Fatalf("q 필터 위반: %s%s", tg.Host, tg.Path)
		}
	}

	// verdict 필터 (부분일치)
	v, _ := listEndpoints(t, "verdict=login")
	for _, tg := range v {
		if !strings.Contains(strings.ToLower(tg.Verdict), "login") {
			t.Fatalf("verdict 필터 위반: %q", tg.Verdict)
		}
	}

	// 페이징: limit=1 이면 1개만, total 은 전체 유지
	page, totalStr := listEndpoints(t, "limit=1&offset=0")
	if len(page) != 1 {
		t.Fatalf("limit=1 → %d개", len(page))
	}
	if totalStr == "" || totalStr == "1" {
		t.Fatalf("X-Total-Count=%q — 필터 없으면 전체 개수여야 함", totalStr)
	}

	// offset 이 total 이상이면 빈 결과(패닉 없이)
	empty, _ := listEndpoints(t, "offset=9999")
	if len(empty) != 0 {
		t.Fatalf("offset 초과 → %d개(0 기대)", len(empty))
	}
}

func TestEndpointDetail(t *testing.T) {
	endpoints.Record("http", "dh:80", "GET", "/api/items/42", []endpoints.Param{{Name: "id", In: "query"}}, false, "")

	// concrete path(/api/items/42) 를 넘겨도 정규화(/api/items/{id})로 조회돼야 함
	req := httptest.NewRequest(http.MethodGet, "/api/endpoints/detail?host=dh:80&path=/api/items/42", nil)
	w := httptest.NewRecorder()
	endpointDetailHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("detail code=%d, want 200", w.Code)
	}
	var n endpoints.OutNode
	if err := json.NewDecoder(w.Body).Decode(&n); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n.Count == 0 {
		t.Fatal("detail count=0")
	}
	if n.FirstSeen == "" || n.LastSeen == "" {
		t.Fatalf("발견 시각 비어있음 first=%q last=%q", n.FirstSeen, n.LastSeen)
	}

	// 없는 경로 → 404
	req2 := httptest.NewRequest(http.MethodGet, "/api/endpoints/detail?host=dh:80&path=/nope", nil)
	w2 := httptest.NewRecorder()
	endpointDetailHandler(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("없는 경로 code=%d, want 404", w2.Code)
	}

	// 파라미터 누락 → 400
	req3 := httptest.NewRequest(http.MethodGet, "/api/endpoints/detail", nil)
	w3 := httptest.NewRecorder()
	endpointDetailHandler(w3, req3)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("파라미터 누락 code=%d, want 400", w3.Code)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// TestEndpointsSourceAndVerifiedFilter — 소스 필터와 unverified 노출 토글 (이슈 #28).
func TestEndpointsSourceAndVerifiedFilter(t *testing.T) {
	endpoints.Reset()
	// spec 1건, 크롤(static-regex) 1건 → 크롤 것을 강등(unverified).
	endpoints.RecordSpec("http", "hv:80", "GET", "/api/spec", nil, false, "")
	endpoints.RecordFrom(endpoints.SrcStaticRegex, "http", "hv:80", "GET", "/guessed", nil, false, "")
	endpoints.MarkUnverified("hv:80", "/guessed")

	// 기본(무파라미터): unverified 제외 → /guessed 안 보임.
	base, _ := listEndpoints(t, "host=hv")
	for _, tg := range base {
		if tg.Path == "/guessed" {
			t.Error("기본 조회에 unverified /guessed 가 보인다 — verified 만 나와야 한다")
		}
	}
	if !hasPath(base, "/api/spec") {
		t.Error("verified /api/spec 이 안 보인다")
	}

	// include_unverified=true → /guessed 노출.
	all, _ := listEndpoints(t, "host=hv&include_unverified=true")
	if !hasPath(all, "/guessed") {
		t.Error("include_unverified=true 인데 /guessed 가 안 보인다")
	}

	// source 필터: spec 만.
	specOnly, _ := listEndpoints(t, "host=hv&include_unverified=true&source=spec")
	if !hasPath(specOnly, "/api/spec") || hasPath(specOnly, "/guessed") {
		t.Errorf("source=spec 필터 오작동: %v", pathsOf(specOnly))
	}
	for _, tg := range specOnly {
		if tg.Source != "spec" {
			t.Errorf("source=spec 필터에 %q 가 섞임", tg.Source)
		}
	}
}

func hasPath(ts []endpoints.Target, p string) bool {
	for _, t := range ts {
		if t.Path == p {
			return true
		}
	}
	return false
}

func pathsOf(ts []endpoints.Target) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Path)
	}
	return out
}
