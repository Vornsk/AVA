package detector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
)

// TestSessionPersistence — 스캔 중 세션이 만료되면 자동 재로그인 후 재시도로 정상 진단이 이어지는지.
// 서버: 유효 세션(sid=good)일 때만 반사 XSS를 응답. 만료(다른 sid) → "Please log in" 로그아웃 표식.
// /login POST → Set-Cookie sid=good. detector 는 첫 요청이 로그아웃으로 보이면 재로그인·재시도해야 함.
func TestSessionPersistence(t *testing.T) {
	var mu sync.Mutex
	valid := map[string]bool{} // 발급된 유효 세션

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			mu.Lock()
			valid["good"] = true
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "good", Path: "/"})
			_, _ = w.Write([]byte("welcome"))
			return
		}
		c, _ := r.Cookie("sid")
		mu.Lock()
		ok := c != nil && valid[c.Value]
		mu.Unlock()
		if !ok {
			_, _ = w.Write([]byte("<html>Please log in to continue</html>")) // 로그아웃 표식
			return
		}
		// 인증됨 → 취약(반사 XSS)
		_, _ = w.Write([]byte("<html><body>you sent: " + r.URL.Query().Get("q") + "</body></html>"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")

	// 만료된 세션으로 시작 + 재로그인 절차 설정.
	inj := auth.New()
	inj.Set(auth.Config{Cookies: map[string]string{"sid": "stale"}})
	inj.SetLogin(auth.LoginSeq{
		URL:       srv.URL + "/login",
		Method:    "POST",
		Fields:    map[string]string{"user": "admin", "pass": "admin"},
		LoggedOut: "(?i)please log in",
	})

	tgt := endpoints.Target{Scheme: "https", Host: host, Path: "/", Params: []endpoints.Param{{Name: "q", In: "query"}}}

	// 재로그인 없으면 만료 세션 → 로그아웃 페이지 → XSS 미탐이어야 정상. 재로그인 덕에 탐지돼야 함.
	fs := (reflectedInput{}).Detect(context.Background(), tgt, srv.Client(), inj)
	if !hasVuln(fs, "반사") {
		t.Fatalf("세션 만료 자동 재로그인 실패 → XSS 미탐: %+v", fs)
	}

	// 재로그인으로 injector 쿠키가 갱신됐는지.
	if inj.Snapshot()["cookies"][0] != "sid" {
		t.Errorf("쿠키 스냅샷 예상과 다름: %+v", inj.Snapshot())
	}
}

// TestNoReloginWithoutConfig — 재로그인 절차 미설정 시엔 재로그인하지 않는다(보수적).
func TestNoReloginWithoutConfig(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>Please log in</html>")) // 항상 로그아웃
	}))
	defer srv.Close()
	inj := auth.New() // 로그인 절차 없음
	if inj.LoginEnabled() {
		t.Fatal("설정 없이 LoginEnabled true")
	}
	tgt := endpoints.Target{Scheme: "https", Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "q", In: "query"}}}
	if fs := (reflectedInput{}).Detect(context.Background(), tgt, srv.Client(), inj); len(fs) != 0 {
		t.Errorf("로그아웃 페이지 → 미탐 기대(재로그인 없음), got %d", len(fs))
	}
}
