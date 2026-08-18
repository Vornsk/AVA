package crawler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

func contains(ss []string, sub string) bool {
	for _, s := range ss {
		if s == sub {
			return true
		}
	}
	return false
}

// TestExtractAPIEndpoints — SPA JS에서 fetch/axios·ajax url·절대경로·절대URL을 뽑고,
// 정적 에셋·스코프 밖은 제외하는지 검증(JS 실행 없이 공격면 발굴).
func TestExtractAPIEndpoints(t *testing.T) {
	scope.Configure([]string{"app.test"}, nil, nil) // app.test 만 스코프
	base, _ := url.Parse("https://app.test/")

	js := `
		fetch("/api/v1/users?role=admin");
		axios.post('/api/orders', body);
		$.ajax({ url: "/rest/account/balance" });
		const asset = "/static/main.css";       // 에셋 → 제외
		const img = '/img/logo.png';             // 에셋 → 제외
		const ext = "https://evil.cdn.com/track"; // 스코프 밖 → 제외
		const abs = "https://app.test/api/search?q=x";
		const route = "/dashboard/settings";
	`
	got := extractAPIEndpoints(js, base)

	for _, want := range []string{
		"https://app.test/api/v1/users?role=admin",
		"https://app.test/api/orders",
		"https://app.test/rest/account/balance",
		"https://app.test/api/search?q=x",
		"https://app.test/dashboard/settings",
	} {
		if !contains(got, want) {
			t.Errorf("미추출: %s\n got=%v", want, got)
		}
	}
	// 에셋·스코프 밖은 없어야 함.
	for _, bad := range []string{
		"https://app.test/static/main.css",
		"https://app.test/img/logo.png",
		"https://evil.cdn.com/track",
	} {
		if contains(got, bad) {
			t.Errorf("제외돼야 함: %s", bad)
		}
	}
}

// TestCrawlSPA_EndToEnd — SPA 셸(빈 HTML+JS 번들)을 크롤하면 JS 안 API가 공격면에 등록되는지.
// 정적 크롤러라면 놓칠 /api/profile 을 JS 번들 분석으로 발굴해야 한다.
func TestCrawlSPA_EndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`fetch("/api/profile?id=1"); axios.post("/api/logout");`))
			return
		}
		// 실재하는 API 는 JSON 을 준다. 라이브니스 검증(#26)이 SPA 셸과 구분하는 근거이므로
		// 셸로 뭉뚱그리면 정규식으로 발굴한 /api/profile 이 실재하지 않는 것으로 강등된다.
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":1,"name":"alice"}`))
			return
		}
		// SPA 셸: 링크 없이 JS 번들만(정적 크롤러는 여기서 막힘).
		_, _ = w.Write([]byte(`<html><body><div id="root"></div><script src="/app.js"></script></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	scope.Configure([]string{u.Hostname()}, nil, nil)

	res := Start(srv.URL, Options{MaxPages: 10, MaxDepth: 2})
	for i := 0; i < 50; i++ { // 최대 ~5s 대기
		if r, _ := Status(res.ID); r.Status != "진행" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	found := false
	for _, tg := range endpoints.Targets() {
		if tg.Host == u.Host && strings.HasPrefix(tg.Path, "/api/profile") {
			found = true
		}
	}
	if !found {
		t.Errorf("JS 번들의 /api/profile 이 공격면에 등록되지 않음\nTargets=%v", endpoints.Targets())
	}
}

// TestScriptSrcs — <script src> 절대 URL을 뽑는다.
func TestScriptSrcs(t *testing.T) {
	base, _ := url.Parse("https://app.test/")
	html := `<html><head>
		<script src="/assets/app.9f2.js"></script>
		<script src="https://app.test/vendor.js"></script>
		<script>console.log('inline')</script>
	</head></html>`
	got := scriptSrcs(html, base)
	if !contains(got, "https://app.test/assets/app.9f2.js") || !contains(got, "https://app.test/vendor.js") {
		t.Errorf("script src 추출 실패: %v", got)
	}
}
