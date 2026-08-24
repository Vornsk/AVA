package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/finding"
)

func TestReflectedInput(t *testing.T) {
	// 쿼리 파라미터 q의 값을 그대로 반사하는 서버.
	// ★ Content-Type 을 명시한다 (이슈 #54). 예전 이 테스트는 평문을 반환했고 Go 가 그걸
	// text/plain 으로 스니핑했다 — 즉 브라우저가 실행하지 않는 응답을 XSS 로 보고하는
	// #49 오탐 5건과 똑같은 상황을 정답으로 고정해 두고 있었다.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>you sent: " + r.URL.Query().Get("q") + "</body></html>"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	tgt := endpoints.Target{Host: host, Path: "/", Params: []endpoints.Param{{Name: "q", In: "query"}}}

	fs := reflectedInput{}.Detect(context.Background(), tgt, srv.Client(), auth.Default())
	if len(fs) == 0 {
		t.Fatal("reflected payload should produce a finding")
	}
	if fs[0].Detector != "reflected-input" || fs[0].Param != "q" {
		t.Errorf("finding = %+v", fs[0])
	}
}

// 세션 쿠키(있으면 200, 없으면 401)를 흉내내는 핸들러 팩토리.
func sessionServer(body func(user string) string) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "401", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(body(c.Value)))
	}))
}

func hasVuln(fs []finding.Finding, sub string) bool {
	for _, f := range fs {
		if strings.Contains(f.Vuln, sub) {
			return true
		}
	}
	return false
}

// 특권 경로가 누구에게나 200 → 접근통제 미흡(broken). t.Auth 플래그와 무관하게 경로로 판별.
func TestMultiIdentityPrivilegedPathExposed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("admin panel for everyone"))
	}))
	defer srv.Close()
	auth.SetIdentities([]auth.Identity{{Name: "user1"}, {Name: "user2"}})
	defer auth.SetIdentities(nil)

	tgt := endpoints.Target{Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/admin"}
	fs := multiIdentity{}.Detect(context.Background(), tgt, srv.Client(), auth.Default())
	if !hasVuln(fs, "접근통제 미흡") {
		t.Error("privileged path reachable by anon should flag 접근통제 미흡")
	}
}

// 세션 강제(anon 401) + 인증 신원 간 동일 응답 → 수평권한/IDOR.
func TestMultiIdentityHorizontal(t *testing.T) {
	srv := sessionServer(func(string) string { return "order #1001 same for all" }) // 소유자 무시
	defer srv.Close()
	auth.SetIdentities([]auth.Identity{
		{Name: "user1", Cookies: map[string]string{"session": "s1"}},
		{Name: "user2", Cookies: map[string]string{"session": "s2"}},
	})
	defer auth.SetIdentities(nil)

	tgt := endpoints.Target{Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/orders", Auth: true}
	fs := multiIdentity{}.Detect(context.Background(), tgt, srv.Client(), auth.Default())
	if !hasVuln(fs, "IDOR") {
		t.Error("identical response across sessions on auth-enforced endpoint should flag IDOR")
	}
}

// 오탐 방지: 공개 페이지(비특권, 전원 200)·정상 보호(anon 401, 신원별 상이)는 무발동.
func TestMultiIdentityNoFalsePositive(t *testing.T) {
	auth.SetIdentities([]auth.Identity{
		{Name: "user1", Cookies: map[string]string{"session": "s1"}},
		{Name: "user2", Cookies: map[string]string{"session": "s2"}},
	})
	defer auth.SetIdentities(nil)

	// 공개 홈: 비특권 경로, 전원 200 동일.
	pub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("public home"))
	}))
	defer pub.Close()
	pubTgt := endpoints.Target{Host: strings.TrimPrefix(pub.URL, "https://"), Path: "/", Auth: true}
	if fs := (multiIdentity{}).Detect(context.Background(), pubTgt, pub.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("public page should not flag, got %d: %+v", len(fs), fs)
	}

	// 정상 보호: anon 401, 신원별 상이(개인화) → 접근통제·IDOR 모두 무발동.
	prot := sessionServer(func(user string) string { return "profile of " + user }) // 신원별 상이
	defer prot.Close()
	protTgt := endpoints.Target{Host: strings.TrimPrefix(prot.URL, "https://"), Path: "/profile", Auth: true}
	if fs := (multiIdentity{}).Detect(context.Background(), protTgt, prot.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("properly protected+personalized page should not flag, got %d: %+v", len(fs), fs)
	}
}

// 역할별 세션 서버: admin 세션이면 관리자 뷰, 그 외 세션이면 lowFn(role 검사에 따라).
func roleServer(adminBody string, low func(user string) (int, string)) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "401", http.StatusUnauthorized)
			return
		}
		if c.Value == "admintok" {
			_, _ = w.Write([]byte(adminBody))
			return
		}
		code, body := low(c.Value)
		if code != 200 {
			http.Error(w, body, code)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
}

// 수직 권한상승: 특권 경로에서 저권한이 관리자와 동일 응답(역할 무검사) → 발동.
func TestVerticalPrivEscBroken(t *testing.T) {
	// 저권한도 관리자와 동일한 사용자 목록을 본다(broken).
	srv := roleServer("USER LIST admin/user1/user2", func(string) (int, string) {
		return 200, "USER LIST admin/user1/user2"
	})
	defer srv.Close()
	auth.SetIdentities([]auth.Identity{
		{Name: "admin", Privileged: true, Cookies: map[string]string{"session": "admintok"}},
		{Name: "user1", Cookies: map[string]string{"session": "s1"}},
	})
	defer auth.SetIdentities(nil)

	tgt := endpoints.Target{Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/manage/users", Auth: true}
	fs := verticalPrivEsc{}.Detect(context.Background(), tgt, srv.Client(), auth.Default())
	if !hasVuln(fs, "수직 권한상승") {
		t.Error("low-priv seeing admin-identical response on privileged path should flag 수직 권한상승")
	}
}

// 정상 인가(저권한 403) 대조군 → 무발동.
func TestVerticalPrivEscProtected(t *testing.T) {
	srv := roleServer("AUDIT LOG", func(string) (int, string) { return 403, "forbidden" }) // 저권한 거부
	defer srv.Close()
	auth.SetIdentities([]auth.Identity{
		{Name: "admin", Privileged: true, Cookies: map[string]string{"session": "admintok"}},
		{Name: "user1", Cookies: map[string]string{"session": "s1"}},
	})
	defer auth.SetIdentities(nil)

	tgt := endpoints.Target{Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/admin/audit", Auth: true}
	if fs := (verticalPrivEsc{}).Detect(context.Background(), tgt, srv.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("properly authorized endpoint should not flag privesc, got %d: %+v", len(fs), fs)
	}
}

// SQL 주입: 따옴표 주입 시 DB 에러 노출 → 발동 / 정상 파라미터엔 무발동.
func TestSQLInjection(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("id"), "'\"") {
			http.Error(w, "You have an error in your SQL syntax near '''", 500)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")

	tgt := endpoints.Target{Host: host, Path: "/item", Params: []endpoints.Param{{Name: "id", In: "query"}}}
	if fs := (sqlInjection{}).Detect(context.Background(), tgt, srv.Client(), auth.Default()); !hasVuln(fs, "SQL 주입") {
		t.Error("SQL error on quote injection should flag SQL 주입")
	}
	// 대조군: 에러를 안 내는 서버 → 무발동.
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer safe.Close()
	safeTgt := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/item", Params: []endpoints.Param{{Name: "id", In: "query"}}}
	if fs := (sqlInjection{}).Detect(context.Background(), safeTgt, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("no SQL error → no finding, got %d", len(fs))
	}
}

// 블라인드 SQLi: 참(AND 1=1)≈원본·거짓(AND 1=2)≠원본 이면 발동 / 파라미터화면 무발동.
func TestBlindSQLi(t *testing.T) {
	// 취약: id 의 불린 조건을 결과에 반영(에러 없음).
	blindTrue := func(id string) bool {
		s := strings.ReplaceAll(strings.ReplaceAll(strings.ToUpper(id), "'", ""), " ", "")
		if i := strings.Index(s, "--"); i >= 0 {
			s = s[:i]
		}
		if i := strings.Index(s, "AND"); i >= 0 {
			if eq := strings.SplitN(s[i+3:], "=", 2); len(eq) == 2 {
				return eq[0] == eq[1]
			}
			return false
		}
		return id == "1"
	}
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if blindTrue(r.URL.Query().Get("id")) {
			_, _ = w.Write([]byte("<h2>User found</h2><p>Alice gold member profile details here</p>"))
		} else {
			_, _ = w.Write([]byte("<h2>No user</h2>"))
		}
	}))
	defer vuln.Close()
	tgt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/user", Params: []endpoints.Param{{Name: "id", In: "query", Sample: "1"}}}
	if fs := (blindSQLi{}).Detect(context.Background(), tgt, vuln.Client(), auth.Default()); !hasVuln(fs, "블라인드") {
		t.Error("boolean-blind injectable endpoint should flag 블라인드 SQLi")
	}

	// 안전(파라미터화): id 리터럴 비교 → 주입 무효 → 참/거짓 응답 동일 → 무발동.
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "1" {
			_, _ = w.Write([]byte("<h2>User found</h2><p>Alice gold member profile details here</p>"))
		} else {
			_, _ = w.Write([]byte("<h2>No user</h2>"))
		}
	}))
	defer safe.Close()
	safeTgt := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/user-safe", Params: []endpoints.Param{{Name: "id", In: "query", Sample: "1"}}}
	if fs := (blindSQLi{}).Detect(context.Background(), safeTgt, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("parameterized endpoint → no blind SQLi finding, got %d: %+v", len(fs), fs)
	}
}

// 컨텍스트 인식 XSS: 실행 가능한 위치의 반사만 발동, textarea 등 비실행 컨테이너 반사는 무발동.
// TestStoredXSS — 주입값이 마커 없는 재조회 응답에 실행가능하게 남으면 저장형(반사형과 구분).
func TestStoredXSS(t *testing.T) {
	// 저장형: 쿼리 c로 받은 값을 서버 메모리에 저장, 모든 GET 응답에 그대로 노출.
	var mu sync.Mutex
	var storedBody string
	stored := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if v := r.URL.Query().Get("c"); v != "" {
			storedBody += v // 저장(검증 없이)
		}
		_, _ = w.Write([]byte("<html><body>comments: " + storedBody + "</body></html>"))
	}))
	defer stored.Close()
	st := endpoints.Target{Host: strings.TrimPrefix(stored.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "c", In: "query"}}}
	if fs := (storedXSS{}).Detect(context.Background(), st, stored.Client(), auth.Default()); !hasVuln(fs, "저장형") {
		t.Errorf("stored payload persisting into clean fetch should flag, got %+v", fs)
	}

	// 반사형(저장 안 함): 값이 그 요청에만 반사 → 클린 재조회엔 없음 → 저장형 무발동(반사형 detector 몫).
	reflectOnly := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>echo: " + r.URL.Query().Get("c") + "</body></html>"))
	}))
	defer reflectOnly.Close()
	rt := endpoints.Target{Host: strings.TrimPrefix(reflectOnly.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "c", In: "query"}}}
	if fs := (storedXSS{}).Detect(context.Background(), rt, reflectOnly.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("reflected-only should NOT flag as stored, got %d", len(fs))
	}
}

// TestDomXSS — 동일 script 블록에서 source→sink 공존 시 정적 힌트, 없으면 무발동.
func TestDomXSS(t *testing.T) {
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><script>var x=location.hash; document.getElementById('o').innerHTML=x;</script></html>`))
	}))
	defer vuln.Close()
	vt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/"}
	if fs := (domXSS{}).Detect(context.Background(), vt, vuln.Client(), auth.Default()); !hasVuln(fs, "DOM") {
		t.Errorf("source→sink co-occurrence should flag, got %+v", fs)
	}

	// sink만 있고 source 없음 → 무발동(오탐 배제).
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><script>document.getElementById('o').innerHTML='static';</script></html>`))
	}))
	defer safe.Close()
	stt := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/"}
	if fs := (domXSS{}).Detect(context.Background(), stt, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("sink without source should NOT flag, got %d", len(fs))
	}
}

// TestBodyJSONInjection — 공격 detector가 쿼리뿐 아니라 폼바디·JSON 바디 파라미터에도 주입하는지.
func TestBodyJSONInjection(t *testing.T) {
	// 폼바디의 q에 따옴표가 들어오면 MySQL 오류를 반환하는 서버.
	formSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.PostFormValue("q"), "'") {
			_, _ = w.Write([]byte("You have an error in your SQL syntax; check the manual for MySQL"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer formSrv.Close()
	formTgt := endpoints.Target{
		Host: strings.TrimPrefix(formSrv.URL, "https://"), Path: "/", Methods: []string{"POST"},
		Params: []endpoints.Param{{Name: "q", In: "body"}},
	}
	fs := (sqlInjection{}).Detect(context.Background(), formTgt, formSrv.Client(), auth.Default())
	if !hasVuln(fs, "SQL 주입") {
		t.Errorf("폼바디 주입 미탐: %+v", fs)
	} else if fs[0].Method != "POST" {
		t.Errorf("폼바디 주입 method=%s, want POST", fs[0].Method)
	}

	// JSON 바디의 q에 따옴표가 들어오면 MySQL 오류를 반환하는 서버.
	jsonSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &in)
		if s, _ := in["q"].(string); strings.Contains(s, "'") {
			_, _ = w.Write([]byte("mysql_fetch_array(): supplied argument is not a valid MySQL result"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer jsonSrv.Close()
	jsonTgt := endpoints.Target{
		Host: strings.TrimPrefix(jsonSrv.URL, "https://"), Path: "/", Methods: []string{"POST"},
		Params: []endpoints.Param{{Name: "q", In: "json"}},
	}
	fs = (sqlInjection{}).Detect(context.Background(), jsonTgt, jsonSrv.Client(), auth.Default())
	if !hasVuln(fs, "SQL 주입") {
		t.Errorf("JSON 바디 주입 미탐: %+v", fs)
	}
}

// TestNestedJSONInjection — 중첩 JSON 키(user.name)·형제 보존·배열 인덱스 재구성 검증.
func TestNestedJSONInjection(t *testing.T) {
	var trigBody []byte // user.name 주입이 트리거한 요청 본문
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		// user.name 에 따옴표 주입되면 MySQL 오류.
		user, _ := in["user"].(map[string]any)
		if s, _ := user["name"].(string); strings.Contains(s, "'") {
			trigBody = body
			_, _ = w.Write([]byte("You have an error in your SQL syntax; check the manual for MySQL"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	tgt := endpoints.Target{
		Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/", Methods: []string{"POST"},
		Params: []endpoints.Param{
			{Name: "user.name", In: "json", Sample: "alice"},
			{Name: "user.role", In: "json", Sample: "guest"}, // 형제 leaf 보존 확인용
		},
	}
	fs := (sqlInjection{}).Detect(context.Background(), tgt, srv.Client(), auth.Default())
	if !hasVuln(fs, "SQL 주입") {
		t.Fatalf("중첩 JSON 주입 미탐: %+v", fs)
	}
	// 트리거 요청이 중첩 구조 + 형제 보존인지 확인.
	var sent map[string]any
	_ = json.Unmarshal(trigBody, &sent)
	u, ok := sent["user"].(map[string]any)
	if !ok {
		t.Fatalf("user 객체 재구성 실패: %s", trigBody)
	}
	if s, _ := u["name"].(string); !strings.Contains(s, "'") {
		t.Errorf("user.name 에 payload 미주입: %v", u)
	}
	if u["role"] != "guest" {
		t.Errorf("형제 leaf(user.role) 미보존: %v", u)
	}
}

// TestCmdInjection — 출력 기반 커맨드 인젝션(id 출력 노출) 탐지 + 정상 응답 무발동.
func TestCmdInjection(t *testing.T) {
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("host")
		if strings.Contains(q, "id") || strings.Contains(q, "passwd") { // 명령이 실행된 것처럼 출력
			_, _ = w.Write([]byte("PING output\nuid=33(www-data) gid=33(www-data) groups=33(www-data)\n"))
			return
		}
		_, _ = w.Write([]byte("PING " + q))
	}))
	defer vuln.Close()
	vt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "host", In: "query"}}}
	if fs := (cmdInjection{}).Detect(context.Background(), vt, vuln.Client(), auth.Default()); !hasVuln(fs, "커맨드 인젝션") {
		t.Errorf("커맨드 출력 노출 → 탐지 기대, got %+v", fs)
	}

	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("PING " + r.URL.Query().Get("host") + " ok")) // 그대로 에코, 실행 안 함
	}))
	defer safe.Close()
	st := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "host", In: "query"}}}
	if fs := (cmdInjection{}).Detect(context.Background(), st, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("명령 미실행(단순 에코) → 무발동 기대, got %d", len(fs))
	}
}

// TestSSRF — url류 파라미터로 내부 메타데이터 노출 시 탐지 + 비-url 파라미터·정상은 무발동.
func TestSSRF(t *testing.T) {
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("url")
		if strings.Contains(u, "169.254.169.254") { // 서버가 메타데이터를 대신 가져와 노출
			_, _ = w.Write([]byte("ami-id: ami-12345\ninstance-id: i-abc\niam/security-credentials/role"))
			return
		}
		_, _ = w.Write([]byte("fetched: " + u))
	}))
	defer vuln.Close()
	vt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "url", In: "query"}}}
	if fs := (ssrf{}).Detect(context.Background(), vt, vuln.Client(), auth.Default()); !hasVuln(fs, "SSRF") {
		t.Errorf("메타데이터 노출 → SSRF 탐지 기대, got %+v", fs)
	}

	// url류가 아닌 파라미터(comment)는 대상 아님 → 무발동.
	nt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "comment", In: "query"}}}
	if fs := (ssrf{}).Detect(context.Background(), nt, vuln.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("비-url 파라미터 → 무발동 기대, got %d", len(fs))
	}
}

// TestSSTI — 템플릿 식이 서버에서 평가되면 탐지, 그대로 반사(미평가)면 무발동.
func TestSSTI(t *testing.T) {
	// 취약: {{7333*7333}} 등 식을 평가해 결과값을 응답에 반영.
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("name")
		if strings.Contains(q, "7333*7333") { // 템플릿 평가 시뮬
			_, _ = w.Write([]byte("Hello 53772889 !"))
			return
		}
		_, _ = w.Write([]byte("Hello " + q))
	}))
	defer vuln.Close()
	vt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "name", In: "query"}}}
	if fs := (ssti{}).Detect(context.Background(), vt, vuln.Client(), auth.Default()); !hasVuln(fs, "템플릿") {
		t.Errorf("템플릿 평가 → SSTI 탐지 기대, got %+v", fs)
	}

	// 안전: 식을 그대로 반사(미평가) → 무발동(단순 반사와 구분).
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello " + r.URL.Query().Get("name"))) // 원본 그대로
	}))
	defer safe.Close()
	st := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "name", In: "query"}}}
	if fs := (ssti{}).Detect(context.Background(), st, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("식 반사(미평가) → 무발동 기대, got %d", len(fs))
	}
}

// TestXXE — XML 외부 엔티티로 /etc/passwd 노출 시 탐지, 처리 안 하면 무발동.
func TestXXE(t *testing.T) {
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "file:///etc/passwd") { // XXE 파서가 엔티티 확장 시뮬
			_, _ = w.Write([]byte("<r>root:x:0:0:root:/root:/bin/bash</r>"))
			return
		}
		_, _ = w.Write([]byte("<r>ok</r>"))
	}))
	defer vuln.Close()
	vt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/api/xml", Methods: []string{"POST"}}
	if fs := (xxe{}).Detect(context.Background(), vt, vuln.Client(), auth.Default()); !hasVuln(fs, "XXE") {
		t.Errorf("외부 엔티티 파일 노출 → XXE 탐지 기대, got %+v", fs)
	}

	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte("<r>ok</r>")) // 엔티티 미처리
	}))
	defer safe.Close()
	st := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/api/xml", Methods: []string{"POST"}}
	if fs := (xxe{}).Detect(context.Background(), st, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("엔티티 미처리 → 무발동 기대, got %d", len(fs))
	}
}

// TestLDAPInjection — LDAP 특수문자 주입 시 LDAP 오류 노출 탐지 + 정상 무발동.
func TestLDAPInjection(t *testing.T) {
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("user"), "*()|") { // 필터 깨짐 → LDAP 오류
			_, _ = w.Write([]byte("javax.naming.directory.InvalidSearchFilterException: invalid attribute"))
			return
		}
		_, _ = w.Write([]byte("welcome"))
	}))
	defer vuln.Close()
	vt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "user", In: "query"}}}
	if fs := (ldapInjection{}).Detect(context.Background(), vt, vuln.Client(), auth.Default()); !hasVuln(fs, "LDAP") {
		t.Errorf("LDAP 오류 노출 → 탐지 기대, got %+v", fs)
	}
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("welcome " + r.URL.Query().Get("user"))) // 오류 없음
	}))
	defer safe.Close()
	st := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "user", In: "query"}}}
	if fs := (ldapInjection{}).Detect(context.Background(), st, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("LDAP 오류 없음 → 무발동 기대, got %d", len(fs))
	}
}

// TestSSIInjection — SSI 지시자 실행(마커 출력) 탐지 + 그대로 반사(미실행) 무발동.
func TestSSIInjection(t *testing.T) {
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("c")
		if strings.Contains(q, "#exec") { // SSI 실행 시뮬 → 지시자 대신 마커 출력
			_, _ = w.Write([]byte("comment: SSI7333OK done"))
			return
		}
		_, _ = w.Write([]byte("comment: " + q))
	}))
	defer vuln.Close()
	vt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "c", In: "query"}}}
	if fs := (ssiInjection{}).Detect(context.Background(), vt, vuln.Client(), auth.Default()); !hasVuln(fs, "SSI") {
		t.Errorf("SSI 실행 → 탐지 기대, got %+v", fs)
	}
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("comment: " + r.URL.Query().Get("c"))) // 지시자 그대로 반사(미실행)
	}))
	defer safe.Close()
	st := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/", Params: []endpoints.Param{{Name: "c", In: "query"}}}
	if fs := (ssiInjection{}).Detect(context.Background(), st, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("지시자 반사(미실행) → 무발동 기대, got %d", len(fs))
	}
}

func TestReflectedContext(t *testing.T) {
	tgt := func(host string) endpoints.Target {
		return endpoints.Target{Host: host, Path: "/", Params: []endpoints.Param{{Name: "q", In: "query"}}}
	}
	// 실행 컨텍스트(본문 텍스트) 반사 → 발동.
	exec := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>" + r.URL.Query().Get("q") + "</body></html>"))
	}))
	defer exec.Close()
	if fs := (reflectedInput{}).Detect(context.Background(), tgt(strings.TrimPrefix(exec.URL, "https://")), exec.Client(), auth.Default()); !hasVuln(fs, "반사") {
		t.Error("executable-context reflection should flag")
	}
	// 비실행 컨테이너(textarea) 반사 → 무발동(오탐 배제).
	inert := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><textarea>" + r.URL.Query().Get("q") + "</textarea></html>"))
	}))
	defer inert.Close()
	if fs := (reflectedInput{}).Detect(context.Background(), tgt(strings.TrimPrefix(inert.URL, "https://")), inert.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("reflection inside textarea should NOT flag, got %d", len(fs))
	}
	// HTML 인코딩 반사 → 무발동(app이 이스케이프함).
	esc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := strings.ReplaceAll(strings.ReplaceAll(r.URL.Query().Get("q"), "<", "&lt;"), ">", "&gt;")
		_, _ = w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer esc.Close()
	if fs := (reflectedInput{}).Detect(context.Background(), tgt(strings.TrimPrefix(esc.URL, "https://")), esc.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("HTML-encoded reflection should NOT flag, got %d", len(fs))
	}
}

// 동적 콘텐츠 견고성: 응답에 매 요청 다른 CSRF 토큰이 있어도 idor 동일-응답 판정이 유지.
func TestNormalizeRobustDifferential(t *testing.T) {
	auth.SetIdentities([]auth.Identity{
		{Name: "user1", Cookies: map[string]string{"session": "s1"}},
		{Name: "user2", Cookies: map[string]string{"session": "s2"}},
	})
	defer auth.SetIdentities(nil)
	// 세션 강제(anon 401) + 인증 신원 동일 콘텐츠지만 매 응답 다른 토큰 삽입.
	tok := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("session"); err != nil {
			http.Error(w, "401", 401)
			return
		}
		tok++
		fmt.Fprintf(w, "<input name='csrf_token' value='%016x'>order #1001 shared", tok*99991)
	}))
	defer srv.Close()
	tgt := endpoints.Target{Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/orders", Auth: true}
	if fs := (multiIdentity{}).Detect(context.Background(), tgt, srv.Client(), auth.Default()); !hasVuln(fs, "IDOR") {
		t.Error("동적 토큰이 달라도 정규화 후 동일 응답으로 IDOR 판정돼야 함")
	}
}

// 시간 기반 블라인드 SQLi: 지연 페이로드에 응답이 느려지면 발동 / 파라미터화(지연 없음) 무발동.
func TestTimeBlindSQLi(t *testing.T) {
	sleepSecs := func(id string) int { // SLEEP(N) 추출(취약 시뮬)
		low := strings.ToLower(id)
		if i := strings.Index(low, "sleep("); i >= 0 {
			rest := low[i+6:]
			if j := strings.IndexByte(rest, ')'); j >= 0 {
				n, _ := strconv.Atoi(strings.TrimSpace(rest[:j]))
				if n > 3 {
					n = 3
				}
				return n
			}
		}
		return 0
	}
	// 취약: 주입된 SLEEP 실행, 응답 내용은 항상 동일.
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d := sleepSecs(r.URL.Query().Get("id")); d > 0 {
			time.Sleep(time.Duration(d) * time.Second)
		}
		_, _ = w.Write([]byte("report"))
	}))
	defer vuln.Close()
	vt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/report", Params: []endpoints.Param{{Name: "id", In: "query", Sample: "1"}}}
	if fs := (timeBlindSQLi{}).Detect(context.Background(), vt, vuln.Client(), auth.Default()); !hasVuln(fs, "시간 기반") {
		t.Error("delay payload slowing response should flag 시간 기반 블라인드 SQLi")
	}

	// 안전(파라미터화): 지연 무시 → 항상 빠름 → 무발동.
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("report"))
	}))
	defer safe.Close()
	st := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/report-safe", Params: []endpoints.Param{{Name: "id", In: "query", Sample: "1"}}}
	if fs := (timeBlindSQLi{}).Detect(context.Background(), st, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("no delay → no finding, got %d: %+v", len(fs), fs)
	}
}

// 경로 순회: 순회 주입 시 파일 내용 노출 → 발동.
func TestPathTraversal(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()
	tgt := endpoints.Target{Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/download", Params: []endpoints.Param{{Name: "file", In: "query"}}}
	if fs := (pathTraversal{}).Detect(context.Background(), tgt, srv.Client(), auth.Default()); !hasVuln(fs, "경로 순회") {
		t.Error("passwd content on traversal should flag 경로 순회")
	}
}

// 오픈 리다이렉트: 외부 호스트로 302 → 발동 / 내부 경로만 허용하면 무발동.
func TestOpenRedirect(t *testing.T) {
	// 취약: url 을 그대로 302.
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)
	}))
	defer vuln.Close()
	tgt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/go", Params: []endpoints.Param{{Name: "url", In: "query"}}}
	if fs := (openRedirect{}).Detect(context.Background(), tgt, vuln.Client(), auth.Default()); !hasVuln(fs, "오픈 리다이렉트") {
		t.Error("external 302 should flag 오픈 리다이렉트")
	}
	// 정상: 내부 경로만 허용, 외부 거부 → 무발동.
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := r.URL.Query().Get("url")
		if strings.HasPrefix(d, "/") && !strings.HasPrefix(d, "//") {
			http.Redirect(w, r, d, http.StatusFound)
			return
		}
		http.Error(w, "bad", 400)
	}))
	defer safe.Close()
	safeTgt := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/safe-go", Params: []endpoints.Param{{Name: "url", In: "query"}}}
	if fs := (openRedirect{}).Detect(context.Background(), safeTgt, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("origin-restricted redirect → no finding, got %d: %+v", len(fs), fs)
	}
}

// 파일 업로드: 위험 확장자(.php) 수용 → 발동 / 거부(대조군) → 무발동.
func TestFileUpload(t *testing.T) {
	fileParam := []endpoints.Param{{Name: "file", In: "file", Sample: "a.txt"}}
	// 취약: 확장자 검증 없이 수용.
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, err := r.FormFile("file"); err != nil {
			http.Error(w, "no file", 400)
			return
		}
		_, _ = w.Write([]byte("uploaded"))
	}))
	defer vuln.Close()
	vt := endpoints.Target{Host: strings.TrimPrefix(vuln.URL, "https://"), Path: "/upload", Methods: []string{"POST"}, Params: fileParam, Auth: true}
	if fs := (fileUpload{}).Detect(context.Background(), vt, vuln.Client(), auth.Default()); !hasVuln(fs, "파일 업로드") {
		t.Error("dangerous extension accepted should flag 파일 업로드 제한 미흡")
	}

	// 안전(대조군): .php 거부.
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hdr, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "no file", 400)
			return
		}
		if strings.HasSuffix(strings.ToLower(hdr.Filename), ".php") {
			http.Error(w, "forbidden ext", 403)
			return
		}
		_, _ = w.Write([]byte("uploaded"))
	}))
	defer safe.Close()
	st := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/upload-safe", Methods: []string{"POST"}, Params: fileParam, Auth: true}
	if fs := (fileUpload{}).Detect(context.Background(), st, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("rejected dangerous extension → no finding, got %d: %+v", len(fs), fs)
	}
}

// CSRF: 상태변경(POST)+세션 인증+토큰 없음 → 발동 / 토큰 있거나 GET 이면 무발동.
func TestCSRFMissing(t *testing.T) {
	base := func(methods []string, params []endpoints.Param, auth bool) endpoints.Target {
		return endpoints.Target{Host: "h", Path: "/transfer", Methods: methods, Params: params, Auth: auth}
	}
	// 취약: POST + 세션 인증 + anti-CSRF 토큰 없음.
	vuln := base([]string{"POST"}, []endpoints.Param{{Name: "amount", In: "body"}, {Name: "to", In: "body"}}, true)
	if fs := (csrfMissing{}).Detect(context.Background(), vuln, nil, nil); !hasVuln(fs, "CSRF") {
		t.Error("POST+auth+no token should flag CSRF")
	}
	// 안전: csrf_token 파라미터 존재.
	withTok := base([]string{"POST"}, []endpoints.Param{{Name: "amount", In: "body"}, {Name: "csrf_token", In: "body"}}, true)
	if fs := (csrfMissing{}).Detect(context.Background(), withTok, nil, nil); len(fs) != 0 {
		t.Errorf("token present → no CSRF finding, got %d", len(fs))
	}
	// 안전: GET(상태변경 아님).
	get := base([]string{"GET"}, nil, true)
	if fs := (csrfMissing{}).Detect(context.Background(), get, nil, nil); len(fs) != 0 {
		t.Errorf("GET → no CSRF finding, got %d", len(fs))
	}
	// 안전: 비인증(세션 없음) 상태변경 — CSRF 문맥 아님.
	noAuth := base([]string{"POST"}, []endpoints.Param{{Name: "q", In: "body"}}, false)
	if fs := (csrfMissing{}).Detect(context.Background(), noAuth, nil, nil); len(fs) != 0 {
		t.Errorf("no session → no CSRF finding, got %d", len(fs))
	}
}

// 쿠키 보안속성: HttpOnly/Secure 없는 Set-Cookie → 발동 / 전부 설정되면 무발동.
func TestCookieSecurity(t *testing.T) {
	weak := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sid=abc123") // 속성 없음
		_, _ = w.Write([]byte("ok"))
	}))
	defer weak.Close()
	wt := endpoints.Target{Host: strings.TrimPrefix(weak.URL, "https://"), Path: "/"}
	if fs := (cookieSecurity{}).Detect(context.Background(), wt, weak.Client(), auth.Default()); !hasVuln(fs, "쿠키 보안속성") {
		t.Error("attribute-less cookie should flag")
	}
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sid=abc123; HttpOnly; Secure; SameSite=Strict")
		_, _ = w.Write([]byte("ok"))
	}))
	defer safe.Close()
	st := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/"}
	if fs := (cookieSecurity{}).Detect(context.Background(), st, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("fully-attributed cookie → no finding, got %d", len(fs))
	}
}

// 위험 HTTP 메소드: OPTIONS Allow 에 PUT/DELETE 등 → 발동 / 안전 메소드만이면 무발동.
func TestHTTPMethod(t *testing.T) {
	danger := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "GET, POST, PUT, DELETE, TRACE")
	}))
	defer danger.Close()
	dt := endpoints.Target{Host: strings.TrimPrefix(danger.URL, "https://"), Path: "/api"}
	if fs := (httpMethod{}).Detect(context.Background(), dt, danger.Client(), auth.Default()); !hasVuln(fs, "위험 HTTP 메소드") {
		t.Error("dangerous methods in Allow should flag")
	}
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "GET, POST, HEAD, OPTIONS")
	}))
	defer safe.Close()
	st := endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/api"}
	if fs := (httpMethod{}).Detect(context.Background(), st, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("safe methods only → no finding, got %d", len(fs))
	}
}

// 디렉터리 인덱싱: 상위 디렉터리가 목록 노출 → 발동 / 정상 페이지면 무발동.
func TestDirIndexing(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/files/" {
			_, _ = w.Write([]byte("<html><head><title>Index of /files</title></head><body><h1>Index of /files</h1><a href='a.txt'>a.txt</a></body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html>normal page</html>"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	// /files/a.txt → 상위 /files/ 요청 → 목록 노출 → 발동
	if fs := (dirIndexing{}).Detect(context.Background(), endpoints.Target{Host: host, Path: "/files/a.txt"}, srv.Client(), auth.Default()); !hasVuln(fs, "디렉터리 인덱싱") {
		t.Error("directory listing should flag")
	}
	// 상위가 정상 페이지 → 무발동
	safe := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>normal</html>")) }))
	defer safe.Close()
	if fs := (dirIndexing{}).Detect(context.Background(), endpoints.Target{Host: strings.TrimPrefix(safe.URL, "https://"), Path: "/app/page.php"}, safe.Client(), auth.Default()); len(fs) != 0 {
		t.Errorf("normal parent dir → no finding, got %d", len(fs))
	}
}

func TestMultiIdentityNeedsTwo(t *testing.T) {
	auth.SetIdentities(nil) // anon 만 → 비교 불가
	defer auth.SetIdentities(nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	tgt := endpoints.Target{Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/x", Auth: true}
	fs := (multiIdentity{}).Detect(context.Background(), tgt, srv.Client(), auth.Default())
	if len(fs) != 0 {
		t.Errorf("with only anon, expected no findings, got %d", len(fs))
	}
}

// 이슈 #54 — 브라우저가 렌더링하지 않는 응답의 반사는 XSS 가 아니다.
//
// #49 벤치의 오탐 5건이 전부 이 유형이었다(P 82.8% 를 깎아먹던 단일 원인):
// 값이 raw 로 반사되지만 응답이 text/plain 이라 실행되지 않는다.
// ★ 미상(헤더 없음)은 지우지 않는다 — 브라우저가 스니핑하므로 정탐일 수 있다.
func TestReflectedInputContentType(t *testing.T) {
	serve := func(ct string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ct == "" {
				w.Header()["Content-Type"] = nil // 헤더 자체를 빼서 미상 상황을 만든다
			} else {
				w.Header().Set("Content-Type", ct)
			}
			_, _ = w.Write([]byte("<html><body>" + r.URL.Query().Get("q") + "</body></html>"))
		}))
	}
	cases := []struct {
		ct   string
		want bool // 발견이 나와야 하는가
	}{
		{"text/html; charset=utf-8", true},
		{"application/xhtml+xml", true},
		{"image/svg+xml", true},
		{"", true}, // 미상 → 스니핑 가능성. 지우지 않는다
		{"text/plain; charset=utf-8", false},
		{"application/json", false},
		{"text/csv", false},
		{"application/octet-stream", false},
	}
	for _, c := range cases {
		srv := serve(c.ct)
		tgt := endpoints.Target{Host: strings.TrimPrefix(srv.URL, "https://"), Path: "/",
			Params: []endpoints.Param{{Name: "q", In: "query"}}}
		fs := reflectedInput{}.Detect(context.Background(), tgt, srv.Client(), auth.Default())
		srv.Close()
		if got := len(fs) > 0; got != c.want {
			t.Errorf("content-type %q → 발견 %d건, want %v", c.ct, len(fs), c.want)
		}
		if c.want && len(fs) > 0 && fs[0].ContentType == "" && c.ct != "" {
			t.Errorf("content-type %q 인데 finding.ContentType 이 비었다", c.ct)
		}
	}
}
