package auth

import "net/http"

// Identity — 진단용 신원 (관리자·일반·비인가 등). 다중 신원 진단(FR-3.6)에서 교차 요청에 사용.
type Identity struct {
	Name       string
	Cookies    map[string]string
	Headers    map[string]string
	Privileged bool // 고권한(관리자) 신원. 수직 권한상승 점검에서 저권한과 대조 기준.
}

// Apply — 이 신원의 쿠키·헤더를 요청에 적용 (교차 요청용).
func (id Identity) Apply(req *http.Request) {
	for k, v := range id.Headers {
		req.Header.Set(k, v)
	}
	for n, v := range id.Cookies {
		req.AddCookie(&http.Cookie{Name: n, Value: v})
	}
}
