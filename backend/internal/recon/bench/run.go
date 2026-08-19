package bench

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/crawler"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

// authClient — Relogin 용 HTTP 클라이언트(self-signed 허용).
func authClient() *http.Client {
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

// ApplyAuth — gt.Auth 를 전역 injector 에 설정한다(#31). 반환 cleanup 으로 대상 간 격리.
// 인증 설정이 nil 이면 비인증(기존 동작) — 하위호환.
func ApplyAuth(a *Auth) func() {
	auth.Set(auth.Config{})        // 초기화(이전 대상 잔여 제거)
	auth.SetLogin(auth.LoginSeq{}) // 로그인 시퀀스 초기화
	if a != nil {
		auth.Set(auth.Config{Cookies: a.Cookies, Headers: a.Headers})
		if a.Login != nil {
			auth.SetLogin(auth.LoginSeq{
				URL: a.Login.URL, Method: a.Login.Method, Fields: a.Login.Fields,
				TokenURL: a.Login.TokenURL, TokenField: a.Login.TokenField,
				TokenParam: a.Login.TokenParam, LoggedOut: a.Login.LoggedOut,
			})
		}
	}
	return func() { auth.Set(auth.Config{}); auth.SetLogin(auth.LoginSeq{}) }
}

// LoginNow — 로그인 시퀀스가 설정돼 있으면 지금 실행해 세션을 확보. 성공 여부 반환.
func LoginNow() bool {
	if !auth.Default().LoginEnabled() {
		return false
	}
	return auth.Default().Relogin(authClient())
}

// Reachable — 대상 base 가 응답하는가(기동 여부 프로브). 어떤 HTTP 응답이든 오면 true.
// Juice Shop 은 https://localhost 자기서명이라 InsecureSkipVerify 로 접속만 확인한다.
func Reachable(base string) bool {
	c := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := c.Get(base)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

// RunProfile — 한 프로파일로 정찰을 돌리고 발견 집합을 수집한다.
// 전역 트리를 Reset 해 프로파일 간 격리를 보장한다(이슈 #22의 실행 격리).
//
//	반환: 발견 엔드포인트(method 확장), 제품 구분 수(rawCount=팽창률 분자), 페이지수(≈요청수), 소요시간.
func RunProfile(seed, mode string, maxPages int, timeout time.Duration) (disc []Endpoint, rawCount, pages int, dur time.Duration, err error) {
	endpoints.Reset()

	// 크롤러는 scope.Allowed(host,path) 로 모든 fetch 를 게이트한다. 대상 호스트를 스코프에 넣는다.
	if u, perr := url.Parse(seed); perr == nil && u.Hostname() != "" {
		scope.Configure([]string{u.Hostname()}, nil, nil)
	}

	// 로그인 시퀀스가 설정돼 있으면 프로파일마다 세션을 새로 확보(#31). (5s 쿨다운으로 폭주 방지)
	if auth.Default().LoginEnabled() {
		auth.Default().Relogin(authClient())
	}

	start := time.Now()
	// discover 프로파일은 능동 발견만 켠 static 크롤이다 (#27). 옵트인이므로 여기서만 켠다.
	opts := crawler.Options{Mode: mode, MaxPages: maxPages}
	if mode == "discover" {
		opts.Mode, opts.Discover = "static", true
	}
	if mode == "auth-delta" { // 비인증→인증 두 패스로 auth-only 식별 (#38)
		opts.Mode, opts.AuthDelta = "static", true
	}
	res := crawler.Start(seed, opts)

	deadline := time.Now().Add(timeout)
	for {
		st, ok := crawler.Status(res.ID)
		if ok {
			res = st
		}
		if res.Status != "진행" {
			break
		}
		if time.Now().After(deadline) {
			_ = crawler.Cancel(res.ID)
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	dur = time.Since(start)

	// 발견 집합: 제품 트리의 Target(정규화 노드별 구체 경로)을 method 로 펼친다.
	for _, t := range endpoints.Targets() {
		for _, m := range t.Methods {
			disc = append(disc, Endpoint{Method: m, Path: t.Path})
		}
	}
	rawCount = len(disc) // 제품이 구분한 (method,path) 수 — 하네스 canonical 로 접히기 전
	return disc, rawCount, res.Pages, dur, nil
}
