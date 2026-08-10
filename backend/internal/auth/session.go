// 세션 지속성(FR-2.5): 긴 스캔 중 세션이 만료되면 로그인 절차를 자동 재실행해 쿠키를 갱신한다.
// 만료 판단은 설정된 정규식(LoggedOut)으로만 활성화 → 오탐 재로그인 없음(보수적).
package auth

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// LoginSeq — 자동 재로그인 절차. LoggedOut(만료 판단 정규식)이 있어야 활성화된다.
type LoginSeq struct {
	URL        string            `yaml:"url" json:"url"`                 // 로그인 요청 URL
	Method     string            `yaml:"method" json:"method"`           // 기본 POST
	Fields     map[string]string `yaml:"fields" json:"fields"`           // 폼 필드(username, password 등)
	TokenURL   string            `yaml:"token_url" json:"token_url"`     // (선택) CSRF 토큰 사전 취득 페이지
	TokenField string            `yaml:"token_field" json:"token_field"` // 응답에서 뽑을 hidden input name(예: user_token)
	TokenParam string            `yaml:"token_param" json:"token_param"` // 로그인 폼에 넣을 토큰 파라미터명(기본 TokenField)
	LoggedOut  string            `yaml:"logged_out" json:"logged_out"`   // 세션 만료 판단 정규식(본문/Location)
}

func (s LoginSeq) enabled() bool { return s.URL != "" && s.LoggedOut != "" }

// SetLogin — 재로그인 절차 지정.
func (in *Injector) SetLogin(s LoginSeq) {
	in.mu.Lock()
	in.login = s
	if s.LoggedOut != "" {
		in.loginRe, _ = regexp.Compile(s.LoggedOut)
	} else {
		in.loginRe = nil
	}
	in.mu.Unlock()
}

// LoginInfo — 로그인 시퀀스 조회용(값 마스킹). 필드는 키 이름만 노출(비밀번호 값 미노출, §8).
type LoginInfo struct {
	Enabled    bool     `json:"enabled"`
	URL        string   `json:"url"`
	Method     string   `json:"method"`
	TokenURL   string   `json:"token_url"`
	TokenField string   `json:"token_field"`
	TokenParam string   `json:"token_param"`
	LoggedOut  string   `json:"logged_out"`
	Fields     []string `json:"fields"` // 폼 필드 키만(값은 미노출)
}

// LoginSnapshot — 현재 로그인 시퀀스(값 마스킹).
func (in *Injector) LoginSnapshot() LoginInfo {
	in.mu.RLock()
	defer in.mu.RUnlock()
	keys := make([]string, 0, len(in.login.Fields))
	for k := range in.login.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return LoginInfo{
		Enabled: in.login.enabled() && in.loginRe != nil,
		URL:     in.login.URL, Method: in.login.Method,
		TokenURL: in.login.TokenURL, TokenField: in.login.TokenField, TokenParam: in.login.TokenParam,
		LoggedOut: in.login.LoggedOut, Fields: keys,
	}
}

// LoginEnabled — 자동 재로그인이 설정됐는가.
func (in *Injector) LoginEnabled() bool {
	in.mu.RLock()
	defer in.mu.RUnlock()
	return in.login.enabled() && in.loginRe != nil
}

// LooksLoggedOut — 응답(상태·Location·본문)이 세션 만료를 나타내는가.
func (in *Injector) LooksLoggedOut(location, body string) bool {
	in.mu.RLock()
	re := in.loginRe
	in.mu.RUnlock()
	if re == nil {
		return false
	}
	return (location != "" && re.MatchString(location)) || re.MatchString(body)
}

// Relogin — 로그인 절차를 재실행해 세션 쿠키를 갱신한다. 단일 실행(loginMu)·쿨다운으로 폭주 방지.
// client 의 Transport(TLS 신뢰)를 재사용하되 임시 쿠키자를 붙여 세션을 흐르게 한다.
func (in *Injector) Relogin(client *http.Client) bool {
	in.loginMu.Lock() // 동시 스캔에서 재로그인 1회만
	defer in.loginMu.Unlock()

	in.mu.RLock()
	seq := in.login
	recent := !in.lastLogin.IsZero() && time.Since(in.lastLogin) < 5*time.Second
	in.mu.RUnlock()
	if !seq.enabled() {
		return false
	}
	if recent {
		return true // 방금 다른 goroutine이 재로그인함 → 갱신된 쿠키 사용
	}

	cookies, ok := runLogin(client, seq)
	in.mu.Lock()
	in.lastLogin = time.Now()
	if ok && len(cookies) > 0 {
		if in.cfg.Cookies == nil {
			in.cfg.Cookies = map[string]string{}
		}
		for k, v := range cookies {
			in.cfg.Cookies[k] = v // 세션 쿠키 갱신
		}
	}
	in.mu.Unlock()
	return ok
}

// runLogin — (선택)토큰 취득 → 로그인 POST. 임시 쿠키자에 쌓인 세션 쿠키를 반환한다.
func runLogin(client *http.Client, seq LoginSeq) (map[string]string, bool) {
	lc := *client // Transport(TLS 신뢰) 재사용
	jar, _ := cookiejar.New(nil)
	lc.Jar = jar
	lc.Timeout = 15 * time.Second

	fields := url.Values{}
	for k, v := range seq.Fields {
		fields.Set(k, v)
	}

	// (선택) CSRF 토큰 사전 취득 — 같은 쿠키자로 GET 해 토큰과 초기 세션을 함께 확보.
	if seq.TokenURL != "" && seq.TokenField != "" {
		if resp, err := lc.Get(seq.TokenURL); err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			re := regexp.MustCompile(`(?i)name=['"]` + regexp.QuoteMeta(seq.TokenField) + `['"][^>]*value=['"]([^'"]+)['"]`)
			if m := re.FindSubmatch(b); m != nil {
				param := seq.TokenParam
				if param == "" {
					param = seq.TokenField
				}
				fields.Set(param, string(m[1]))
			}
		}
	}

	method := strings.ToUpper(seq.Method)
	if method == "" {
		method = "POST"
	}
	req, err := http.NewRequest(method, seq.URL, strings.NewReader(fields.Encode()))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := lc.Do(req)
	if err != nil {
		return nil, false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()

	out := map[string]string{}
	if u, e := url.Parse(seq.URL); e == nil {
		for _, ck := range jar.Cookies(u) {
			out[ck.Name] = ck.Value
		}
	}
	return out, resp.StatusCode < 400 || len(out) > 0
}
