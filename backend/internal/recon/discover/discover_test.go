package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/recon/liveness"
	"proxypoc/internal/scope"
)

// spaBody — 없는 경로에도 돌려주는 SPA 셸. Juice Shop 은 이걸 9393바이트로 준다.
const spaBody = `<!DOCTYPE html><html><head><title>SPA</title></head>` +
	`<body><div id="root"></div><script src="/main.js"></script></body></html>`

// catchAll — 모든 경로에 200 + 같은 HTML 을 주되, real 목록만 진짜 응답을 주는 서버.
func catchAll(t *testing.T, real map[string]func(http.ResponseWriter)) (*httptest.Server, *sync.Map) {
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

func setup(t *testing.T, srv *httptest.Server) *endpoints.Tree {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	scope.Configure([]string{u.Hostname()}, nil, nil)
	t.Cleanup(func() { scope.Configure(nil, nil, nil) })
	return endpoints.NewTree()
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

// TestWordlistShape — embed 된 wordlist 가 실제로 읽히고 규칙을 지키는가.
func TestWordlistShape(t *testing.T) {
	w := Words()
	if len(w) < 100 {
		t.Fatalf("wordlist 항목 %d개 — 너무 적다", len(w))
	}
	seen := map[string]bool{}
	for _, p := range w {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("슬래시로 시작하지 않음: %q", p)
		}
		if strings.HasPrefix(p, "#") || strings.TrimSpace(p) != p {
			t.Errorf("주석·공백이 섞임: %q", p)
		}
		if seen[p] {
			t.Errorf("중복: %q", p)
		}
		seen[p] = true
	}
	// 상태를 바꿀 만한 경로가 섞이면 "GET only·비파괴" 약속이 깨진다.
	for _, bad := range []string{"/logout", "/reset", "/delete", "/shutdown", "/drop"} {
		if seen[bad] {
			t.Errorf("파괴 가능성 있는 경로가 wordlist 에 있다: %q", bad)
		}
	}
	// 이슈가 근거로 든 경로들이 들어 있어야 발견이 가능하다.
	for _, want := range []string{"/support/logs", "/encryptionkeys", "/.well-known/security.txt", "/ftp"} {
		if !seen[want] {
			t.Errorf("%s 가 wordlist 에 없다 — 완료기준 경로다", want)
		}
	}
}

// TestDiscoverFindsUnlinked — ★ 완료기준: unlinked 경로를 찾고 catch-all 은 등록하지 않는다.
func TestDiscoverFindsUnlinked(t *testing.T) {
	dir := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><title>listing directory</title><ul><li>a.md</li></ul></html>"))
	}
	srv, _ := catchAll(t, map[string]func(http.ResponseWriter){
		"/support/logs":   dir,
		"/encryptionkeys": dir,
		"/.well-known/security.txt": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Contact: mailto:sec@example.com\n"))
		},
	})
	tree := setup(t, srv)

	rep := Run(context.Background(), tree, srv.URL, srv.Client(), 0)
	got := tree.Targets()
	for _, want := range []string{"/support/logs", "/encryptionkeys", "/.well-known/security.txt"} {
		if !has(got, want) {
			t.Errorf("unlinked 경로 %s 를 못 찾음\n발견=%v", want, paths(got))
		}
	}

	// ★ soft-404 오탐 0 — catch-all 이 200 을 주는 경로는 한 건도 등록하면 안 된다.
	for _, fake := range []string{"/admin", "/administrator", "/.git/config", "/backup", "/.env", "/config.json"} {
		if has(got, fake) {
			t.Errorf("실재하지 않는 %s 를 등록했다 (catch-all 200)", fake)
		}
	}
	if rep.Found != 3 {
		t.Errorf("발견 %d건 (want 3): %v", rep.Found, rep.FoundList)
	}
	if rep.Rejected == 0 {
		t.Error("버린 후보가 0건 — soft-404 판정이 동작했는지 알 수 없다")
	}
}

// TestDiscoverTagsSourceDiscover — 등록분은 source=discover 이고, 라이브니스 재프로브 대상이 아니다.
func TestDiscoverTagsSourceDiscover(t *testing.T) {
	srv, _ := catchAll(t, map[string]func(http.ResponseWriter){
		"/ftp": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><title>listing directory /ftp</title></html>"))
		},
	})
	tree := setup(t, srv)
	Run(context.Background(), tree, srv.URL, srv.Client(), 0)

	for _, tg := range tree.Targets() {
		if tg.Source != endpoints.SrcDiscover {
			t.Errorf("%s 출처 = %q, want %q", tg.Path, tg.Source, endpoints.SrcDiscover)
		}
	}
	if endpoints.NeedsProbe(endpoints.SrcDiscover) {
		t.Error("discover 가 라이브니스 재프로브 대상이다 — 등록 전에 이미 확인했다")
	}

	// 라이브니스를 돌려도 후보가 0건이어야 한다(요청이 더 나가지 않는다).
	lr := liveness.Run(context.Background(), tree, srv.Client())
	if lr.Candidates != 0 {
		t.Errorf("라이브니스 후보 %d건 — discover 결과를 또 찌른다", lr.Candidates)
	}
	if !has(tree.Targets(), "/ftp") {
		t.Error("라이브니스가 discover 결과를 강등했다")
	}
}

// TestDiscoverHonest404 — 정직하게 404 를 주는 서버에서는 상태코드로만 판정한다.
func TestDiscoverHonest404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backup" {
			_, _ = w.Write([]byte("backup index"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	tree := setup(t, srv)

	rep := Run(context.Background(), tree, srv.URL, srv.Client(), 0)
	if rep.Baseline != "" {
		t.Errorf("정직한 404 서버인데 기준 지문을 잡았다: %q", rep.Baseline)
	}
	if !has(tree.Targets(), "/backup") {
		t.Error("/backup 을 못 찾음")
	}
	if rep.Found != 1 {
		t.Errorf("발견 %d건 (want 1): %v", rep.Found, rep.FoundList)
	}
}

// TestDiscoverAuthWallCountsAsFound — 401/403 은 실재의 증거다(인증 벽 뒤 관리 화면).
func TestDiscoverAuthWallCountsAsFound(t *testing.T) {
	srv, _ := catchAll(t, map[string]func(http.ResponseWriter){
		"/admin": func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
		},
	})
	tree := setup(t, srv)
	Run(context.Background(), tree, srv.URL, srv.Client(), 0)
	if !has(tree.Targets(), "/admin") {
		t.Error("401 을 주는 /admin 을 버렸다 — 인증 벽 뒤 표면을 통째로 놓친다")
	}
}

// TestDiscoverBudget — 요청 예산을 넘지 않고, 소진 사실을 리포트에 남긴다.
func TestDiscoverBudget(t *testing.T) {
	srv, hits := catchAll(t, nil)
	tree := setup(t, srv)

	rep := Run(context.Background(), tree, srv.URL, srv.Client(), 10)
	if rep.Probed > 10 {
		t.Errorf("예산 10건인데 %d건을 보냈다", rep.Probed)
	}
	if !rep.Exhausted {
		t.Error("예산이 소진됐는데 Exhausted 가 false — 사용자가 부분 확인임을 알 수 없다")
	}
	n := 0
	hits.Range(func(_, _ any) bool { n++; return true })
	if n > 10 {
		t.Errorf("서버가 받은 요청 %d건 > 예산 10건", n)
	}
}

// TestDiscoverScopeHard — 스코프 밖으로는 한 건도 나가지 않는다 (FR-2.1).
func TestDiscoverScopeHard(t *testing.T) {
	srv, hits := catchAll(t, nil)
	tree := endpoints.NewTree()
	scope.Configure([]string{"other.example"}, nil, nil) // 대상 호스트를 넣지 않는다
	defer scope.Configure(nil, nil, nil)

	rep := Run(context.Background(), tree, srv.URL, srv.Client(), 0)
	hits.Range(func(k, _ any) bool {
		t.Errorf("스코프 밖으로 요청이 나갔다: %v", k)
		return true
	})
	if rep.Found != 0 {
		t.Errorf("스코프 밖에서 %d건을 등록했다", rep.Found)
	}
}
