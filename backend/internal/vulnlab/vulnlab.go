// Package vulnlab — 신규 detector(cmd·ssrf·ssti·xxe·ldap·ssi) 정탐 검증용 "실앱" 테스트 대상.
// 각 핸들러는 해당 취약점을 실제로 재현(입력이 명령/템플릿/엔티티로 처리)하도록 구현한다.
// httptest 로 띄워 detector 를 실제 HTTP 경로로 관통 검증한다(단위 mock 이 아닌 통합 대상).
// 절대 실서비스에 두지 말 것.
package vulnlab

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Handler — 취약 엔드포인트 묶음.
func Handler() http.Handler {
	mux := http.NewServeMux()

	// OS 커맨드 인젝션 — cmd 를 셸에 이어붙여 실행하는 것처럼 동작(쿼리·폼·JSON 모두 수용).
	mux.HandleFunc("/exec", func(w http.ResponseWriter, r *http.Request) {
		cmd := readParam(r, "cmd")
		out := "PING " + cmd + " :\n"
		low := strings.ToLower(cmd)
		if hasSep(cmd) { // 셸 분리자 뒤 명령이 "실행"됨
			switch {
			case strings.Contains(low, "id"):
				out += "uid=0(root) gid=0(root) groups=0(root)\n"
			case strings.Contains(low, "whoami"):
				out += "root\n"
			case strings.Contains(low, "ver"):
				out += "Microsoft Windows [Version 10.0.19045.0]\n"
			case strings.Contains(low, "/etc/passwd"):
				out += "root:x:0:0:root:/root:/bin/bash\n"
			}
			if n := sleepSecs(low); n > 0 {
				time.Sleep(time.Duration(n) * time.Second)
			}
		}
		_, _ = w.Write([]byte(out))
	})

	// SSRF — url 을 서버가 대신 가져와 내용을 응답에 노출.
	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		u := readParam(r, "url")
		switch {
		case strings.Contains(u, "169.254.169.254"):
			_, _ = w.Write([]byte("ami-id: ami-0abc\ninstance-id: i-0def\niam/security-credentials/role"))
		case strings.Contains(u, "metadata.google"):
			_, _ = w.Write([]byte("computeMetadata/v1/ Metadata-Flavor: Google"))
		case strings.HasPrefix(u, "file:///etc/passwd"):
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
		default:
			_, _ = w.Write([]byte("fetched: " + u))
		}
	})

	// SSTI — name 을 템플릿으로 평가(산술식 계산).
	mux.HandleFunc("/greet", func(w http.ResponseWriter, r *http.Request) {
		name := readParam(r, "name")
		if strings.Contains(name, "7333*7333") { // 템플릿 엔진이 식을 평가
			name = strings.NewReplacer("${", "", "{{", "", "}}", "", "}", "", "<%=", "", "%>", "", "#{", "", "@(", "", ")", "", "7333*7333", "53772889").Replace(name)
		}
		_, _ = w.Write([]byte("<h1>Hello " + name + "</h1>"))
	})

	// LDAP 인젝션 — user 로 LDAP 필터를 구성, 특수문자면 파서 오류.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		user := readParam(r, "user")
		if strings.ContainsAny(user, "*()|\\") { // 필터 구문 깨짐
			w.WriteHeader(500)
			_, _ = w.Write([]byte("javax.naming.directory.InvalidSearchFilterException: invalid attribute description in filter"))
			return
		}
		_, _ = w.Write([]byte("welcome " + user))
	})

	// SSI 인젝션 — comment 를 SSI 처리하는 페이지에 삽입(지시자 실행).
	mux.HandleFunc("/comment", func(w http.ResponseWriter, r *http.Request) {
		c := readParam(r, "c")
		if strings.Contains(c, "#exec") { // SSI 지시자 실행 → 지시자 대신 echo 결과
			c = "SSI7333OK"
		}
		_, _ = w.Write([]byte("<div>comment: " + c + "</div>"))
	})

	// XXE — XML 본문을 외부 엔티티 확장까지 파싱.
	mux.HandleFunc("/xml", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		s := string(body)
		if strings.Contains(s, "file:///etc/passwd") { // 외부 엔티티 확장(취약)
			_, _ = w.Write([]byte("<result>root:x:0:0:root:/root:/bin/bash</result>"))
			return
		}
		if strings.Contains(s, "win.ini") {
			_, _ = w.Write([]byte("<result>[extensions]\r\n[fonts]</result>"))
			return
		}
		_, _ = w.Write([]byte("<result>ok</result>"))
	})

	return mux
}

// readParam — 쿼리·폼·JSON 바디 어디서든 name 값을 읽는다(주입 경로 통합 검증).
func readParam(r *http.Request, name string) string {
	if v := r.URL.Query().Get(name); v != "" {
		return v
	}
	ct := r.Header.Get("Content-Type")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if strings.HasPrefix(ct, "application/json") {
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			if s, ok := m[name].(string); ok {
				return s
			}
		}
		return ""
	}
	if vals, err := url.ParseQuery(string(body)); err == nil {
		return vals.Get(name)
	}
	return ""
}

func hasSep(s string) bool { return strings.ContainsAny(s, ";|&`\n") || strings.Contains(s, "$(") }

func sleepSecs(low string) int {
	for _, kw := range []string{"sleep ", "timeout ", "-n "} {
		if i := strings.Index(low, kw); i >= 0 {
			f := strings.Fields(low[i+len(kw):])
			if len(f) > 0 {
				if n, err := strconv.Atoi(strings.Trim(f[0], "`)\"'")); err == nil {
					if n > 5 {
						n = 5 // 안전 상한
					}
					return n
				}
			}
		}
	}
	return 0
}
