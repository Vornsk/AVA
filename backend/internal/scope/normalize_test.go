package scope

import "testing"

// 스코프 입력 정규화 (관용 입력) — URL 을 통째로 넣어도 호스트만 남아야 한다.
// 이게 안 되면 hostMatch 가 어긋나 크롤이 링크를 다 찾고도 엔드포인트 0개가 된다.
func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"http://192.168.100.5/":        "192.168.100.5",
		"http://192.168.100.5":         "192.168.100.5",
		"https://example.com/path?q=1": "example.com",
		"example.com":                  "example.com",
		"example.com:8080":             "example.com", // hostMatch 는 포트를 안 본다
		"192.168.100.5:80":             "192.168.100.5",
		"  EXAMPLE.com/  ":             "example.com",
		"//example.com/x":              "example.com",
		"":                             "",
		"   ":                          "",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// ★ 이 이슈의 핵심 회귀 — URL 로 스코프를 넣어도 실제 요청이 통과해야 한다.
func TestScopeAcceptsURLFormInput(t *testing.T) {
	e := New([]string{"http://192.168.100.5/"}, nil, nil) // URL 통째로
	if ok, why := e.Allowed("192.168.100.5", "/m_page.php"); !ok {
		t.Errorf("URL 형식 스코프인데 요청이 막혔다: %s", why)
	}
	// Add 도 같은 관용성
	e2 := New(nil, nil, nil)
	e2.Add("https://example.com/login")
	if !e2.InScope("www.example.com") {
		t.Error("Add 가 URL 을 호스트로 정규화하지 못해 서브도메인 매칭 실패")
	}
}
