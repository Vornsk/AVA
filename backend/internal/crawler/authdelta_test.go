package crawler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

// TestAuthDeltaCrawl — ★ 이슈 #38 완료기준: 인증 뒤에만 보이는 표면이 auth-only 로 태깅된다.
//
// 목 서버: 세션 쿠키가 있으면 관리 링크(/admin/panel)를 노출하고, 없으면 안 보여준다.
// 비인증 패스는 /public 만, 인증 패스는 /public + /admin/panel 을 본다 → /admin/panel 이 델타.
func TestAuthDeltaCrawl(t *testing.T) {
	var mu sync.Mutex
	loggedIn := func(r *http.Request) bool {
		c, err := r.Cookie("session")
		return err == nil && c.Value == "ok"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
		_, _ = w.Write([]byte("<html>welcome</html>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/public" {
			_, _ = w.Write([]byte("<html><body>public area</body></html>"))
			return
		}
		if r.URL.Path == "/admin/panel" {
			if !loggedIn(r) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("<html>need login</html>"))
				return
			}
			_, _ = w.Write([]byte("<html><body>admin panel — danger</body></html>"))
			return
		}
		// 홈: 항상 /public 링크, 로그인 시에만 /admin/panel 링크.
		links := `<a href="/public">public</a>`
		if loggedIn(r) {
			links += ` <a href="/admin/panel">admin</a>`
		}
		_, _ = w.Write([]byte("<html><body>home " + links + "</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	endpoints.Reset()
	scope.Configure([]string{u.Hostname()}, nil, nil)
	// 로그인 시퀀스 설정 — /login 을 치면 세션 쿠키를 받는다.
	auth.SetLogin(auth.LoginSeq{
		URL: srv.URL + "/login", Method: "GET", LoggedOut: "need login",
	})
	t.Cleanup(func() {
		scope.Configure(nil, nil, nil)
		auth.SetLogin(auth.LoginSeq{})
		auth.Set(auth.Config{})
		endpoints.Reset()
	})

	res := Start(srv.URL+"/", Options{MaxPages: 20, MaxDepth: 3, NoIngest: true, NoVerify: true, AuthDelta: true})
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if r, ok := Status(res.ID); ok && r.Status != "진행" {
			break
		}
		time.Sleep(80 * time.Millisecond)
	}
	if r, _ := Status(res.ID); r.Status == "진행" {
		t.Fatal("크롤이 끝나지 않음")
	}

	// /admin/panel 은 인증 뒤에만 보였으니 auth-only 여야 하고, /public 은 아니어야 한다.
	var admin, pub *endpoints.Target
	for _, tg := range endpoints.TargetsAll() {
		tg := tg
		switch {
		case strings.HasPrefix(tg.Path, "/admin/panel"):
			admin = &tg
		case tg.Path == "/public":
			pub = &tg
		}
	}
	if admin == nil {
		t.Fatalf("/admin/panel 이 트리에 없다 (인증 패스에서 발견됐어야)\n%v", pathsOfT(endpoints.TargetsAll()))
	}
	if !admin.AuthOnly {
		t.Error("/admin/panel 이 auth-only 로 태깅되지 않았다 — 접근통제 진단 후보를 놓친다")
	}
	if pub == nil {
		t.Fatal("/public 이 트리에 없다")
	}
	if pub.AuthOnly {
		t.Error("/public 이 auth-only 로 잘못 태깅됐다 (비인증 패스에도 있었다)")
	}
	if r, _ := Status(res.ID); r.AuthOnly < 1 {
		t.Errorf("Result.AuthOnly = %d, want >= 1", r.AuthOnly)
	}
}

// TestAuthDeltaNoLoginSeqFallback — 로그인 시퀀스가 없으면 일반 크롤로 동작(auth-only 0).
func TestAuthDeltaNoLoginSeqFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><a href="/x">x</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	endpoints.Reset()
	scope.Configure([]string{u.Hostname()}, nil, nil)
	auth.SetLogin(auth.LoginSeq{}) // 로그인 시퀀스 없음
	t.Cleanup(func() { scope.Configure(nil, nil, nil); endpoints.Reset() })

	res := Start(srv.URL+"/", Options{MaxPages: 10, MaxDepth: 2, NoIngest: true, NoVerify: true, AuthDelta: true})
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if r, ok := Status(res.ID); ok && r.Status != "진행" {
			break
		}
		time.Sleep(80 * time.Millisecond)
	}
	r, _ := Status(res.ID)
	if r.Status != "완료" {
		t.Fatalf("status=%s, want 완료", r.Status)
	}
	if r.AuthOnly != 0 {
		t.Errorf("로그인 시퀀스 없는데 auth-only %d건 — fallback 이 델타를 돌렸다", r.AuthOnly)
	}
	for _, tg := range endpoints.TargetsAll() {
		if tg.AuthOnly {
			t.Errorf("%s 가 auth-only 로 태깅됨 — 델타가 돌지 않아야 한다", tg.Path)
		}
	}
}

func pathsOfT(ts []endpoints.Target) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Path)
	}
	return out
}
