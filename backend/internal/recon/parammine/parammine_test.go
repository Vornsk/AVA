package parammine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

const basePage = `<!DOCTYPE html><html><head><title>search</title></head><body>` +
	`<h1>Search</h1><p>정적 콘텐츠입니다.</p></body></html>`

// hiddenParamServer — /search 에 두 hidden 파라미터를 심는다:
//   - debug: 값을 응답에 반사한다(이름+값 반사)
//   - admin: 값과 무관하게 응답을 200바이트 늘린다(존재 효과, 반사 없음)
// 그 외 파라미터(무의미 대조·role 등)는 무시하고 기준 페이지만 준다.
func hiddenParamServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		body := basePage
		if v := q.Get("debug"); v != "" {
			body += "\n<!-- debug=" + v + " -->" // 값 반사
		}
		if q.Get("admin") != "" {
			body += "\n" + strings.Repeat("X", 200) // 존재 효과(값 무관)
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setup(t *testing.T, srv *httptest.Server, path string) (*endpoints.Tree, string) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	scope.Configure([]string{u.Hostname()}, nil, nil)
	t.Cleanup(func() { scope.Configure(nil, nil, nil) })
	tree := endpoints.NewTree()
	tree.RecordFrom(endpoints.SrcTraffic, u.Scheme, u.Host, "GET", path, nil, false, "")
	return tree, u.Host
}

func minedParams(tree *endpoints.Tree, host, path string) map[string]bool {
	out := map[string]bool{}
	for _, tg := range tree.Targets() {
		if tg.Host != host || tg.Path != path {
			continue
		}
		for _, p := range tg.Params {
			if p.Mined {
				out[p.Name] = true
			}
		}
	}
	return out
}

// TestFindsHiddenParams — ★ 완료기준: 반사·존재효과로 hidden 파라미터를 찾아 Target 에 붙인다.
func TestFindsHiddenParams(t *testing.T) {
	srv := hiddenParamServer(t)
	tree, host := setup(t, srv, "/search")

	rep := Run(context.Background(), tree, srv.Client(), 0)

	mined := minedParams(tree, host, "/search")
	for _, want := range []string{"debug", "admin"} {
		if !mined[want] {
			t.Errorf("hidden 파라미터 %s 미발견\n발견=%v\n리스트=%v", want, keys(mined), rep.FoundList)
		}
	}
	// 서버가 무시하는 이름은 등록하면 안 된다(오탐 0).
	for _, bad := range []string{"role", "token", "redirect", "page", "q"} {
		if mined[bad] {
			t.Errorf("반응 없는 %s 를 등록했다(오탐)", bad)
		}
	}
	if rep.Found < 2 {
		t.Errorf("Found=%d (want ≥2)", rep.Found)
	}
	if rep.Endpoints != 1 {
		t.Errorf("마이닝 엔드포인트=%d (want 1)", rep.Endpoints)
	}
}

// TestNoFalsePositiveOnStatic — 아무것도 반사·변경하지 않는 정적 엔드포인트에선 0건.
func TestNoFalsePositiveOnStatic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(basePage)) // 쿼리 무관 항상 같은 응답
	}))
	defer srv.Close()
	tree, host := setup(t, srv, "/static")

	rep := Run(context.Background(), tree, srv.Client(), 0)
	if rep.Found != 0 {
		t.Errorf("정적 엔드포인트에서 %d건 등록(want 0): %v", rep.Found, rep.FoundList)
	}
	if len(minedParams(tree, host, "/static")) != 0 {
		t.Error("정적 엔드포인트에 mined 파라미터가 붙었다")
	}
}

// TestReflectAllNotFalsePositive — 모든 파라미터 이름·값을 반사하는 엔드포인트는 신호가
// 노이즈이므로 통째로 등록하면 안 된다(반사-투성이 방어).
func TestReflectAllNotFalsePositive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := basePage
		for k, vs := range r.URL.Query() {
			body += "\n" + k + "=" + strings.Join(vs, ",") // 모든 파라미터를 되비춘다
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	tree, host := setup(t, srv, "/echo")

	Run(context.Background(), tree, srv.Client(), 80) // 예산 제한(반사-투성이는 요청이 많다)
	if n := len(minedParams(tree, host, "/echo")); n > 3 {
		t.Errorf("반사-투성이 엔드포인트에서 %d건 등록 — 워드리스트를 통째로 삼켰다", n)
	}
}

// TestBudgetExhausted — 예산을 넘지 않고 소진 사실을 리포트에 남긴다.
func TestBudgetExhausted(t *testing.T) {
	srv := hiddenParamServer(t)
	tree, _ := setup(t, srv, "/search")

	rep := Run(context.Background(), tree, srv.Client(), 4)
	if rep.Probed > 4 {
		t.Errorf("예산 4건인데 %d건 보냈다", rep.Probed)
	}
	if !rep.Exhausted {
		t.Error("예산 소진인데 Exhausted=false")
	}
}

// TestSkipsObservedParams — 이미 관측된 파라미터는 마이닝하지 않는다(중복 방지).
func TestSkipsObservedParams(t *testing.T) {
	srv := hiddenParamServer(t)
	u, _ := url.Parse(srv.URL)
	scope.Configure([]string{u.Hostname()}, nil, nil)
	defer scope.Configure(nil, nil, nil)
	tree := endpoints.NewTree()
	// debug 를 이미 관측된 파라미터로 넣어 둔다.
	tree.RecordFrom(endpoints.SrcTraffic, u.Scheme, u.Host, "GET", "/search",
		[]endpoints.Param{{Name: "debug", In: "query"}}, false, "")

	Run(context.Background(), tree, srv.Client(), 0)
	mined := minedParams(tree, u.Host, "/search")
	if mined["debug"] {
		t.Error("이미 관측된 debug 를 mined 로 다시 표시했다")
	}
	if !mined["admin"] {
		t.Error("admin 은 여전히 발견돼야 한다")
	}
}

// TestWordlistShape — embed 워드리스트가 읽히고 규칙을 지킨다.
func TestWordlistShape(t *testing.T) {
	w := Words()
	if len(w) < 100 {
		t.Fatalf("워드리스트 %d개 — 너무 적다", len(w))
	}
	seen := map[string]bool{}
	for _, p := range w {
		if p != strings.TrimSpace(p) || p == "" || strings.HasPrefix(p, "#") {
			t.Errorf("불량 항목: %q", p)
		}
		if seen[p] {
			t.Errorf("중복: %q", p)
		}
		seen[p] = true
	}
	for _, want := range []string{"debug", "admin", "role", "redirect"} {
		if !seen[want] {
			t.Errorf("%s 가 워드리스트에 없다", want)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
