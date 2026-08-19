package crawler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

// TestDiscoverOptIn — ★ 이슈 #27 완료기준: 옵트인하지 않으면 능동 프로브가 한 건도 안 나간다.
//
// 이 보장이 깨지면 사용자가 켜지도 않은 능동 탐색이 대상 서버로 나간다 — 법적 경계 문제다.
func TestDiscoverOptIn(t *testing.T) {
	var mu sync.Mutex
	hit := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hit[r.URL.Path] = true
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>plain page</body></html>`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	probed := func() []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for p := range hit {
			// wordlist 에만 있는 경로 — 링크로는 절대 도달하지 않는다.
			if strings.HasPrefix(p, "/.git") || p == "/backup" || p == "/.env" || p == "/phpmyadmin" {
				out = append(out, p)
			}
		}
		return out
	}

	run := func(opts Options) {
		endpoints.Reset()
		scope.Configure([]string{u.Hostname()}, nil, nil)
		defer scope.Configure(nil, nil, nil)
		res := Start(srv.URL, opts)
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			if r, ok := Status(res.ID); ok && r.Status != "진행" {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("크롤이 끝나지 않음")
	}

	// 1) 기본값 — Discover 를 켜지 않았다.
	run(Options{MaxPages: 3, MaxDepth: 1, NoIngest: true, NoVerify: true})
	if got := probed(); len(got) > 0 {
		t.Fatalf("옵트인하지 않았는데 능동 프로브가 나갔다: %v", got)
	}

	// 2) 옵트인 — 이제는 나가야 한다(반대 방향도 확인해야 1)이 의미를 갖는다).
	run(Options{MaxPages: 3, MaxDepth: 1, NoIngest: true, NoVerify: true, Discover: true, Budget: 30})
	if got := probed(); len(got) == 0 {
		t.Error("옵트인했는데 능동 프로브가 한 건도 안 나갔다")
	}
}

// TestParamMineOptIn — ★ 이슈 #40 완료기준: 옵트인하지 않으면 파라미터 주입이 한 건도 안 나간다.
func TestParamMineOptIn(t *testing.T) {
	var mu sync.Mutex
	injected := false
	markers := []string{"debug", "admin", "role", "redirect"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		for _, name := range markers {
			if q.Has(name) {
				mu.Lock()
				injected = true
				mu.Unlock()
			}
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>plain page</body></html>`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	wasInjected := func() bool { mu.Lock(); defer mu.Unlock(); return injected }
	reset := func() { mu.Lock(); injected = false; mu.Unlock() }

	run := func(opts Options) {
		endpoints.Reset()
		scope.Configure([]string{u.Hostname()}, nil, nil)
		defer scope.Configure(nil, nil, nil)
		res := Start(srv.URL+"/panel", opts) // 경로 있는 시드 — 마이닝할 GET 타깃이 생긴다
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			if r, ok := Status(res.ID); ok && r.Status != "진행" {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("크롤이 끝나지 않음")
	}

	// 1) 기본값 — ParamMine 을 켜지 않았다.
	reset()
	run(Options{MaxPages: 3, MaxDepth: 1, NoIngest: true, NoVerify: true})
	if wasInjected() {
		t.Fatal("옵트인하지 않았는데 파라미터 주입이 나갔다")
	}

	// 2) 옵트인 — 이제는 주입이 나가야 한다.
	reset()
	run(Options{MaxPages: 3, MaxDepth: 1, NoIngest: true, NoVerify: true, ParamMine: true, MineBudget: 40})
	if !wasInjected() {
		t.Error("옵트인했는데 파라미터 주입이 한 건도 안 나갔다")
	}
}
