package liveness

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

// spaBody — 없는 경로에도 돌려주는 SPA 셸. Juice Shop 은 이걸 9393바이트로 준다.
const spaBody = `<!DOCTYPE html><html><head><title>SPA</title></head>` +
	`<body><div id="root"></div><script src="/main.js"></script></body></html>`

// catchAll — 모든 경로에 200 + 같은 HTML 을 주되, real 목록만 진짜 응답을 주는 서버.
func catchAll(t *testing.T, real map[string]func(w http.ResponseWriter)) (*httptest.Server, *sync.Map) {
	t.Helper()
	hits := &sync.Map{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Store(r.URL.Path, true)
		if h, ok := real[r.URL.Path]; ok {
			h(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte(spaBody))
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

func setup(t *testing.T, srv *httptest.Server) (*endpoints.Tree, string, string) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	scope.Configure([]string{u.Hostname()}, nil, nil)
	t.Cleanup(func() { scope.Configure(nil, nil, nil) })
	return endpoints.NewTree(), u.Scheme, u.Host
}

func paths(ts []endpoints.Target) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Path)
	}
	return out
}

func has(ts []endpoints.Target, p string) bool {
	for _, t := range ts {
		if t.Path == p {
			return true
		}
	}
	return false
}

// TestSoftFourOhFourDemotesFakes — ★ 완료기준: catch-all 서버에서 진짜만 살아남는다.
// 상태코드는 전부 200 이므로 본문 시그니처로만 갈린다.
func TestSoftFourOhFourDemotesFakes(t *testing.T) {
	srv, _ := catchAll(t, map[string]func(http.ResponseWriter){
		"/api/products": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[1,2,3],"total":3}`))
		},
		"/metrics": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("ava_requests_total 42\n"))
		},
	})
	tree, scheme, host := setup(t, srv)

	// 정규식 추출물 4건 — 진짜 2 + SPA 라우트(가짜) 2.
	for _, p := range []string{"/api/products", "/metrics", "/about", "/i18n/ko/common"} {
		tree.RecordFrom(endpoints.SrcStaticRegex, scheme, host, "GET", p, nil, false, "")
	}

	rep := Run(context.Background(), tree, srv.Client())
	if rep.Demoted != 2 {
		t.Fatalf("강등 %d건 (want 2)\n강등목록=%v\n남은대상=%v", rep.Demoted, rep.DemotedList, paths(tree.Targets()))
	}
	got := tree.Targets()
	for _, want := range []string{"/api/products", "/metrics"} {
		if !has(got, want) {
			t.Errorf("진짜 엔드포인트 %s 가 강등됐다 — 재현율 회귀", want)
		}
	}
	for _, gone := range []string{"/about", "/i18n/ko/common"} {
		if has(got, gone) {
			t.Errorf("실재하지 않는 %s 가 남았다", gone)
		}
	}
	// ★ 강등이지 삭제가 아니다 — TargetsAll 에는 그대로 있다.
	all := tree.TargetsAll()
	if len(all) != 4 {
		t.Errorf("TargetsAll = %d건 (want 4) — 강등이 아니라 삭제됐다: %v", len(all), paths(all))
	}
	for _, tg := range all {
		if tg.Path == "/about" && !tg.Unverified {
			t.Error("/about 에 unverified 플래그가 안 붙었다")
		}
	}
}

// TestProbeOnlyLowTrustSources — ★ 완료기준: 면제 등급에는 요청이 나가지 않는다.
func TestProbeOnlyLowTrustSources(t *testing.T) {
	srv, hits := catchAll(t, nil)
	tree, scheme, host := setup(t, srv)

	exempt := map[string]string{
		"/spec/path":    endpoints.SrcSpec,
		"/traffic/path": endpoints.SrcTraffic,
		"/xhr/path":     endpoints.SrcHeadlessXHR,
		"/legacy/path":  "", // 출처를 안 남기던 시절 = 프록시 캡처
	}
	for p, src := range exempt {
		tree.RecordFrom(src, scheme, host, "GET", p, nil, false, "")
	}
	tree.RecordFrom(endpoints.SrcStaticRegex, scheme, host, "GET", "/regex/path", nil, false, "")
	tree.RecordFrom(endpoints.SrcCrawlLink, scheme, host, "GET", "/link/path", nil, false, "")

	rep := Run(context.Background(), tree, srv.Client())
	if rep.Candidates != 2 {
		t.Errorf("후보 %d건 (want 2 — static-regex·crawl-link 만)", rep.Candidates)
	}
	if rep.Skipped != len(exempt) {
		t.Errorf("면제 %d건 (want %d)", rep.Skipped, len(exempt))
	}
	for p := range exempt {
		if _, probed := hits.Load(p); probed {
			t.Errorf("면제 등급 %s 에 요청이 나갔다", p)
		}
	}
	for _, p := range []string{"/regex/path", "/link/path"} {
		if _, probed := hits.Load(p); !probed {
			t.Errorf("프로브 대상 %s 에 요청이 안 나갔다", p)
		}
	}
	// 면제 대상은 전부 살아남는다.
	if n := len(tree.Targets()); n != len(exempt) {
		t.Errorf("남은 대상 %d건 (want %d — 면제분만)", n, len(exempt))
	}
}

// TestAuthWallCountsAsAlive — ★ 401/403 을 강등하면 인증 벽 뒤 엔드포인트를 통째로 잃는다.
func TestAuthWallCountsAsAlive(t *testing.T) {
	srv, _ := catchAll(t, map[string]func(http.ResponseWriter){
		"/api/basket": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
		},
		"/admin": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Forbidden"))
		},
		"/gone": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("nope"))
		},
	})
	tree, scheme, host := setup(t, srv)
	for _, p := range []string{"/api/basket", "/admin", "/gone"} {
		tree.RecordFrom(endpoints.SrcStaticRegex, scheme, host, "GET", p, nil, false, "")
	}

	Run(context.Background(), tree, srv.Client())
	got := tree.Targets()
	for _, want := range []string{"/api/basket", "/admin"} {
		if !has(got, want) {
			t.Errorf("%s 가 강등됐다 — 401/403 은 실재의 증거다", want)
		}
	}
	if has(got, "/gone") {
		t.Error("404 인 /gone 이 남았다")
	}
}

// TestHonest404NoBaseline — 정직하게 404 를 주는 서버에서는 soft-404 비교를 하지 않는다.
func TestHonest404NoBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	tree, scheme, host := setup(t, srv)
	tree.RecordFrom(endpoints.SrcStaticRegex, scheme, host, "GET", "/real", nil, false, "")
	tree.RecordFrom(endpoints.SrcStaticRegex, scheme, host, "GET", "/fake", nil, false, "")

	rep := Run(context.Background(), tree, srv.Client())
	if rep.Baseline != "" {
		t.Errorf("정직한 404 서버인데 baseline 을 잡았다: %q", rep.Baseline)
	}
	got := tree.Targets()
	if !has(got, "/real") {
		t.Error("/real 이 강등됐다")
	}
	if has(got, "/fake") {
		t.Error("404 인 /fake 가 남았다")
	}
}

// TestRandomBodyGivesUp — 응답이 매번 다르면 baseline 을 못 잡으므로 판정을 포기한다(강등 0).
func TestRandomBodyGivesUp(t *testing.T) {
	var n int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		i := n
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(strings.Repeat("x", 100*i))) // 매번 크기가 다르다
	}))
	defer srv.Close()
	tree, scheme, host := setup(t, srv)
	for i := 0; i < 3; i++ {
		tree.RecordFrom(endpoints.SrcStaticRegex, scheme, host, "GET", fmt.Sprintf("/p%d", i), nil, false, "")
	}

	rep := Run(context.Background(), tree, srv.Client())
	if rep.Baseline != "" {
		t.Errorf("응답이 매번 다른데 baseline 을 잡았다: %q", rep.Baseline)
	}
	if rep.Demoted != 0 {
		t.Errorf("판정 불가인데 %d건을 강등했다 — 근거 없는 강등", rep.Demoted)
	}
}

// TestScopeHard — 스코프 밖으로는 프로브가 나가지 않는다 (FR-2.1).
func TestScopeHard(t *testing.T) {
	srv, hits := catchAll(t, nil)
	u, _ := url.Parse(srv.URL)
	tree := endpoints.NewTree()
	tree.RecordFrom(endpoints.SrcStaticRegex, u.Scheme, u.Host, "GET", "/x", nil, false, "")

	scope.Configure([]string{"other.example"}, nil, nil) // 대상 호스트를 넣지 않는다
	defer scope.Configure(nil, nil, nil)

	rep := Run(context.Background(), tree, srv.Client())
	hits.Range(func(k, _ any) bool {
		t.Errorf("스코프 밖으로 요청이 나갔다: %v", k)
		return true
	})
	if rep.Demoted != 0 {
		t.Errorf("요청도 못 보냈는데 %d건 강등", rep.Demoted)
	}
}

// TestVerifiedSourceClearsDemotion — 강등된 노드가 면제 등급으로 다시 잡히면 복구된다.
func TestVerifiedSourceClearsDemotion(t *testing.T) {
	srv, _ := catchAll(t, nil)
	tree, scheme, host := setup(t, srv)
	tree.RecordFrom(endpoints.SrcStaticRegex, scheme, host, "GET", "/maybe", nil, false, "")

	Run(context.Background(), tree, srv.Client())
	if has(tree.Targets(), "/maybe") {
		t.Fatal("사전 조건: 강등돼 있어야 한다")
	}
	// 프록시가 실제 트래픽으로 같은 경로를 잡았다 = 실재한다.
	tree.RecordFrom(endpoints.SrcTraffic, scheme, host, "GET", "/maybe", nil, false, "")
	if !has(tree.Targets(), "/maybe") {
		t.Error("실 트래픽으로 다시 잡혔는데 강등이 유지됐다")
	}
}
