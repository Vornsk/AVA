package crawler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

// TestHeadlessCrawl_Integration — 헤드리스가 JS로만 렌더되는 링크를 발견하는지(정적 크롤러는 놓침).
// Chrome 미설치 시 skip.
func TestHeadlessCrawl_Integration(t *testing.T) {
	if !HeadlessAvailable() {
		t.Skip("Chrome/Chromium 미설치 — 헤드리스 크롤 skip")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/spa-route" {
			_, _ = w.Write([]byte("<html><body>deep page</body></html>"))
			return
		}
		// 정적 HTML엔 링크 없음 — JS가 렌더 후 <a>를 주입(SPA 시뮬).
		_, _ = w.Write([]byte(`<html><body><div id="app"></div>
<script>document.getElementById('app').innerHTML='<a href="/spa-route">go</a>';</script>
</body></html>`))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	scope.Configure([]string{u.Hostname()}, nil, nil)

	res := Start(srv.URL, Options{MaxPages: 10, MaxDepth: 2, Mode: "headless"})
	if res.Mode != "headless" {
		t.Fatalf("mode=%s, want headless", res.Mode)
	}
	for i := 0; i < 100; i++ { // 최대 ~20s
		if r, _ := Status(res.ID); r.Status != "진행" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	found := false
	for _, tg := range endpoints.Targets() {
		if tg.Host == u.Host && tg.Path == "/spa-route" {
			found = true
		}
	}
	if !found {
		t.Errorf("헤드리스가 JS 렌더 링크 /spa-route 를 발견하지 못함\nTargets=%v", endpoints.Targets())
	}
}
