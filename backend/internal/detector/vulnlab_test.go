package detector

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/vulnlab"
)

// TestVulnlabIntegration — 신규 detector 6종을 실제 취약 앱(vulnlab)에 HTTPS로 관통 실행해 정탐 확인.
// 단위 mock 이 아니라 하나의 다중 엔드포인트 앱을 실제 detector 경로로 스캔하는 통합 검증.
func TestVulnlabIntegration(t *testing.T) {
	srv := httptest.NewTLSServer(vulnlab.Handler())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	c := srv.Client()
	inj := auth.Default()
	ctx := context.Background()

	tgt := func(path string, ps ...endpoints.Param) endpoints.Target {
		return endpoints.Target{Scheme: "https", Host: host, Path: path, Methods: []string{"POST"}, Params: ps}
	}
	q := func(n, s string) endpoints.Param { return endpoints.Param{Name: n, In: "query", Sample: s} }

	cases := []struct {
		name string
		det  Detector
		tgt  endpoints.Target
		vuln string
	}{
		{"cmd-injection", cmdInjection{}, tgt("/exec", q("cmd", "127.0.0.1")), "커맨드 인젝션"},
		{"ssrf", ssrf{}, tgt("/fetch", q("url", "http://x/")), "SSRF"},
		{"ssti", ssti{}, tgt("/greet", q("name", "guest")), "템플릿"},
		{"ldap-injection", ldapInjection{}, tgt("/login", q("user", "admin")), "LDAP"},
		{"ssi-injection", ssiInjection{}, tgt("/comment", q("c", "hi")), "SSI"},
		{"xxe", xxe{}, tgt("/xml"), "XXE"},
	}
	for _, tc := range cases {
		fs := tc.det.Detect(ctx, tc.tgt, c, inj)
		if !hasVuln(fs, tc.vuln) {
			t.Errorf("[%s] 정탐 실패: %+v", tc.name, fs)
		} else {
			t.Logf("[%s] 정탐 OK — %s", tc.name, fs[0].Evidence)
		}
	}
}

// TestVulnlabBodyJSONInjection — 바디/JSON 주입 경로도 신규 detector가 관통하는지(cmd-injection).
func TestVulnlabBodyJSONInjection(t *testing.T) {
	srv := httptest.NewTLSServer(vulnlab.Handler())
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")

	// JSON 바디 파라미터로 커맨드 인젝션.
	jt := endpoints.Target{Scheme: "https", Host: host, Path: "/exec", Methods: []string{"POST"},
		Params: []endpoints.Param{{Name: "cmd", In: "json", Sample: "127.0.0.1"}}}
	if fs := (cmdInjection{}).Detect(context.Background(), jt, srv.Client(), auth.Default()); !hasVuln(fs, "커맨드 인젝션") {
		t.Errorf("JSON 바디 커맨드 인젝션 정탐 실패: %+v", fs)
	}
	// 폼 바디 파라미터로 SSTI.
	ft := endpoints.Target{Scheme: "https", Host: host, Path: "/greet", Methods: []string{"POST"},
		Params: []endpoints.Param{{Name: "name", In: "body", Sample: "guest"}}}
	if fs := (ssti{}).Detect(context.Background(), ft, srv.Client(), auth.Default()); !hasVuln(fs, "템플릿") {
		t.Errorf("폼 바디 SSTI 정탐 실패: %+v", fs)
	}
}
