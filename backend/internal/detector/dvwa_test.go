package detector

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
)

const dvwaBase = "http://localhost:4280"

var tokenRe = regexp.MustCompile(`name=['"]user_token['"]\s+value=['"]([0-9a-f]+)['"]`)

// TestDVWAStoredXSS_Integration — 실제 DVWA guestbook(저장형 XSS)로 stored-xss detector 재검증.
// DVWA(localhost:4280)가 없으면 skip. admin/password·security=low 세션으로 진단.
func TestDVWAStoredXSS_Integration(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	// DVWA 가용성 확인.
	if _, err := c.Get(dvwaBase + "/login.php"); err != nil {
		t.Skipf("DVWA 미가동(%s): %v", dvwaBase, err)
	}

	sid := dvwaLogin(t, c)
	if sid == "" {
		t.Skip("DVWA 로그인 실패 — 자격/토큰 흐름 확인 필요(테스트 skip)")
	}

	// 진단용 주입기: 인증 세션 + 보안레벨 low.
	inj := auth.New()
	inj.Set(auth.Config{Cookies: map[string]string{"PHPSESSID": sid, "security": "low"}})

	guestbook := endpoints.Target{
		Scheme: "http", Host: "localhost:4280", Path: "/vulnerabilities/xss_s/",
		Params: []endpoints.Param{
			{Name: "txtName", In: "body", Sample: "tester"},
			{Name: "mtxMessage", In: "body", Sample: "hello"},
			{Name: "btnSign", In: "body", Sample: "Sign Guestbook"},
		},
	}

	fs := (storedXSS{}).Detect(context.Background(), guestbook, c, inj)
	if len(fs) == 0 {
		t.Fatal("DVWA guestbook 저장형 XSS 를 탐지하지 못함")
	}
	t.Logf("탐지: %s / param=%s / conf=%s", fs[0].Vuln, fs[0].Param, fs[0].Confidence)
	t.Logf("증적: %s", fs[0].Response)
}

// TestDVWADomXSS_Integration — 실제 DVWA DOM XSS 페이지(xss_d)로 dom-xss detector 재검증.
// 인라인 스크립트에 source(document.location.href)→sink(document.write) 공존을 정적 탐지.
func TestDVWADomXSS_Integration(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	if _, err := c.Get(dvwaBase + "/login.php"); err != nil {
		t.Skipf("DVWA 미가동(%s): %v", dvwaBase, err)
	}
	sid := dvwaLogin(t, c)
	if sid == "" {
		t.Skip("DVWA 로그인 실패(테스트 skip)")
	}
	inj := auth.New()
	inj.Set(auth.Config{Cookies: map[string]string{"PHPSESSID": sid, "security": "low"}})

	domPage := endpoints.Target{Scheme: "http", Host: "localhost:4280", Path: "/vulnerabilities/xss_d/"}
	fs := (domXSS{}).Detect(context.Background(), domPage, c, inj)
	if len(fs) == 0 {
		t.Fatal("DVWA DOM XSS(xss_d) source→sink 힌트를 탐지하지 못함")
	}
	t.Logf("탐지: %s / conf=%s", fs[0].Vuln, fs[0].Confidence)
	t.Logf("근거: %s", fs[0].Evidence)
}

// TestDVWACmdInjection_Integration — 실제 DVWA Command Injection(/vulnerabilities/exec/)로 cmd-injection 재검증.
func TestDVWACmdInjection_Integration(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 15 * time.Second}
	if _, err := c.Get(dvwaBase + "/login.php"); err != nil {
		t.Skipf("DVWA 미가동(%s): %v", dvwaBase, err)
	}
	sid := dvwaLogin(t, c)
	if sid == "" {
		t.Skip("DVWA 로그인 실패(테스트 skip)")
	}
	inj := auth.New()
	inj.Set(auth.Config{Cookies: map[string]string{"PHPSESSID": sid, "security": "low"}})

	// exec low 폼: ip(주입 대상) + Submit. base 값 뒤에 ;id 가 붙어 실행됨.
	exec := endpoints.Target{
		Scheme: "http", Host: "localhost:4280", Path: "/vulnerabilities/exec/",
		Methods: []string{"POST"},
		Params: []endpoints.Param{
			{Name: "ip", In: "body", Sample: "127.0.0.1"},
			{Name: "Submit", In: "body", Sample: "Submit"},
		},
	}
	fs := (cmdInjection{}).Detect(context.Background(), exec, c, inj)
	if len(fs) == 0 {
		t.Fatal("DVWA Command Injection 을 탐지하지 못함")
	}
	t.Logf("탐지: %s / param=%s / conf=%s", fs[0].Vuln, fs[0].Param, fs[0].Confidence)
	t.Logf("증적: %s", fs[0].Response)
}

// dvwaLogin — DVWA에 admin/password로 로그인하고 PHPSESSID를 반환("" = 실패).
func dvwaLogin(t *testing.T, c *http.Client) string {
	// 1) 로그인 폼에서 user_token(CSRF) 확보.
	resp, err := c.Get(dvwaBase + "/login.php")
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := tokenRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	// 2) 로그인 POST.
	form := url.Values{"username": {"admin"}, "password": {"password"}, "Login": {"Login"}, "user_token": {string(m[1])}}
	resp, err = c.PostForm(dvwaBase+"/login.php", form)
	if err != nil {
		return ""
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// 3) DB 미초기화 상태면 setup.php로 1회 생성 시도(있으면 무시).
	if r2, e := c.Get(dvwaBase + "/vulnerabilities/xss_s/"); e == nil {
		b2, _ := io.ReadAll(r2.Body)
		r2.Body.Close()
		if strings.Contains(string(b2), "login.php") && !strings.Contains(r2.Request.URL.Path, "xss_s") {
			return "" // 로그인 안 됨(리다이렉트)
		}
	}
	u, _ := url.Parse(dvwaBase)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "PHPSESSID" {
			return ck.Value
		}
	}
	return ""
}
