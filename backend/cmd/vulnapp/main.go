// Command vulnapp — 의도적으로 취약한 테스트 대상 (문서 §8 "번들 취약 테스트 대상").
// 자체 회귀 테스트·데모용. 탐지기를 자극하도록 설계하되, 접근통제 점검이 의미 있도록
// 실제로 세션을 강제하는(정상 보호) 엔드포인트와, 강제하지 않는(취약) 엔드포인트를 섞는다:
//
//	공개(인증무관):  /               홈
//	                 /search?q=      반사 XSS
//	                 /product?id=&cat= 다중 파라미터 반사
//	보호(정상):      /dashboard      세션 필요 → anon 401  (접근통제 정상: 오탐이면 안 됨)
//	                 /profile        세션 필요, 신원별 상이 → anon 401 + 민감정보(로그인 뷰)
//	취약(참):        /admin          관리자 경로인데 세션 검사 없음 → 누구나 200 (접근통제 미흡)
//	                 /orders         세션은 필요하나 소유자 검증 없음 → 신원 간 동일 (수평권한/IDOR)
//
// 절대 실서비스에 두지 말 것.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// 세션 쿠키 → 사용자. project.config.yaml 의 identities 와 맞춘다.
var sessions = map[string]string{
	"sess-user1": "user1",
	"sess-user2": "user2",
	"sess-admin": "admin",
}

// 관리자 세션인가.
func isAdmin(r *http.Request) bool { return whoami(r) == "admin" }

// extractSleep — id 에 주입된 지연 페이로드(SLEEP(N)/pg_sleep(N)/WAITFOR DELAY '0:0:N')의 초를 추출.
// 취약한 시간 기반 블라인드 쿼리 시뮬레이션용. 안전 상한 5초.
func extractSleep(id string) int {
	low := strings.ToLower(id)
	for _, kw := range []string{"sleep(", "pg_sleep("} { // pg_sleep 도 "sleep(" 로 매칭됨
		if i := strings.Index(low, kw); i >= 0 {
			rest := low[i+len(kw):]
			if j := strings.IndexByte(rest, ')'); j >= 0 {
				return capSleep(rest[:j])
			}
		}
	}
	if i := strings.Index(low, "delay '0:0:"); i >= 0 { // MSSQL
		rest := low[i+len("delay '0:0:"):]
		if j := strings.IndexByte(rest, '\''); j >= 0 {
			return capSleep(rest[:j])
		}
	}
	return 0
}

func capSleep(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	if n < 0 {
		n = 0
	}
	if n > 5 {
		n = 5 // 안전 상한(테스트/데모 앱 보호)
	}
	return n
}

// blindTrue — 취약한 불린-블라인드 쿼리 시뮬레이션: id 에 주입된 AND 조건의 참/거짓을 결과에 반영.
// 정상 파라미터화라면 리터럴 비교로 무효화되지만, 여기선 조건이 그대로 평가된다(취약).
func blindTrue(id string) bool {
	s := strings.ToUpper(id)
	if i := strings.Index(s, "--"); i >= 0 { // 주석 종료 제거
		s = s[:i]
	}
	s = strings.ReplaceAll(strings.ReplaceAll(s, "'", ""), " ", "")
	if i := strings.Index(s, "AND"); i >= 0 { // 주입된 조건 평가
		cond := s[i+3:]
		if eq := strings.SplitN(cond, "=", 2); len(eq) == 2 {
			return eq[0] == eq[1] // 1=1 → 참, 1=2 → 거짓
		}
		return false
	}
	return strings.TrimSpace(id) == "1" // 주입 없음: 유효 id
}

// whoami — 세션 쿠키로 사용자 식별. 없으면 "".
func whoami(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return sessions[c.Value]
}

func main() {
	addr := flag.String("addr", "127.0.0.1:9099", "리슨 주소")
	flag.Parse()

	mux := http.NewServeMux()

	// 홈 — 공개. 공격면(링크) 노출.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `<html><body><h1>Vulnerable Test App</h1>
<a href="/search?q=hello">search</a> <a href="/product?id=1&cat=books">product</a>
<a href="/dashboard">dashboard</a> <a href="/profile">profile</a>
<a href="/orders">orders</a> <a href="/admin">admin</a></body></html>`)
	})

	// 반사 XSS — q 를 검증/이스케이프 없이 반사 (공개).
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><h2>Results for: %s</h2></body></html>", q) // 취약: 미이스케이프
	})

	// 다중 파라미터 반사 (공개).
	mux.HandleFunc("/product", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		cat := r.URL.Query().Get("cat")
		fmt.Fprintf(w, "<html><body>product id=%s category=%s</body></html>", id, cat)
	})

	// 대시보드 — 보호(정상): 세션 없으면 401. 접근통제가 제대로 동작 → 오탐이면 안 됨.
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		u := whoami(r)
		if u == "" {
			http.Error(w, "401 인증 필요", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "<html><body><h1>Dashboard</h1><p>환영합니다, %s 님</p></body></html>", u) // 신원별 상이
	})

	// 프로필 — 보호(정상) + 민감정보: 세션 없으면 401. 신원별 상이한 개인정보.
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		u := whoami(r)
		if u == "" {
			http.Error(w, "401 인증 필요", http.StatusUnauthorized)
			return
		}
		// 신원별 다른 개인정보 → 수평권한 IDOR 오탐이 나면 안 됨(user1≠user2).
		rrn := map[string]string{"user1": "900101-1234567", "user2": "880202-2345678"}[u]
		// Luhn 유효한 테스트 카드번호(Visa/Mastercard 표준 테스트 번호)
		card := map[string]string{"user1": "4111-1111-1111-1111", "user2": "5555-5555-5555-4444"}[u]
		fmt.Fprintf(w, `<html><body>
<p>이름: %s</p>
<p>주민등록번호: %s</p>
<p>카드번호: %s</p>
<p>계좌번호: 110-234-567890</p>
</body></html>`, u, rrn, card) // 취약(민감정보 평문) 이나 접근통제는 정상
	})

	// 주문 — 취약(IDOR): 세션은 필요하나 소유자 검증이 없어 아무 세션이나 동일한 주문을 본다.
	mux.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
		u := whoami(r)
		if u == "" {
			http.Error(w, "401 인증 필요", http.StatusUnauthorized)
			return
		}
		// 소유자와 무관하게 같은 주문 노출 → user1·user2 동일 응답(수평권한 미흡).
		fmt.Fprint(w, `<html><body><h1>Order #1001</h1><p>결제계좌: 110-234-567890 금액: 250000</p></body></html>`)
	})

	// 관리자 — 취약(접근통제 미흡): 관리자 경로인데 세션 검사가 전혀 없어 누구나 200.
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><h1>Admin Panel</h1><p>전체 사용자 목록·설정</p></body></html>`) // 취약: 인증 없음
	})

	// 사용자 관리 — 취약(수직 권한상승): 세션은 필요하나 관리자 역할 검사가 없어
	// 저권한 사용자도 관리자와 동일한 사용자 목록을 본다. anon 은 401.
	mux.HandleFunc("/manage/users", func(w http.ResponseWriter, r *http.Request) {
		if whoami(r) == "" {
			http.Error(w, "401 인증 필요", http.StatusUnauthorized)
			return
		}
		// 역할 무검사 → 저권한도 관리자와 동일 응답(수직 권한상승).
		fmt.Fprint(w, `<html><body><h1>User Management</h1>
<ul><li>user1</li><li>user2</li><li>admin</li></ul></body></html>`)
	})

	// 감사로그 — 정상(권한 검사 O): 관리자만 200, 저권한은 403, anon 은 401.
	// 수직 권한상승 detector 의 오탐 대조군(정탐 회피 검증).
	mux.HandleFunc("/admin/audit", func(w http.ResponseWriter, r *http.Request) {
		u := whoami(r)
		if u == "" {
			http.Error(w, "401 인증 필요", http.StatusUnauthorized)
			return
		}
		if !isAdmin(r) {
			http.Error(w, "403 권한 없음", http.StatusForbidden) // 정상 인가: 저권한 거부
			return
		}
		fmt.Fprint(w, `<html><body><h1>Audit Log</h1><p>2026-08-06 admin 로그인</p></body></html>`)
	})

	// SQL 주입 — 취약: id 에 따옴표가 들어오면 구문오류로 DB 에러를 그대로 노출.
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, "'\"") { // 취약: 미검증 → SQL 구문오류
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Error: You have an error in your SQL syntax; check the manual "+
				"that corresponds to your MySQL server version for the right syntax near '%s'", id)
			return
		}
		fmt.Fprintf(w, "<html><body>item id=%s</body></html>", id)
	})

	// 시간 기반 블라인드 SQLi — 취약: 주입된 지연(SLEEP 등)이 실행되지만 응답 내용은 항상 동일.
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		if d := extractSleep(r.URL.Query().Get("id")); d > 0 { // 취약: 주입된 지연 실행
			time.Sleep(time.Duration(d) * time.Second)
		}
		fmt.Fprint(w, "<html><body>Report generated.</body></html>") // 완전 블라인드(항상 동일)
	})

	// 안전 리포트 — 정상(대조군): id 리터럴 취급 → 주입 무효, 지연 없음.
	mux.HandleFunc("/report-safe", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>Report generated.</body></html>")
	})

	// 블라인드 SQLi — 취약: 에러는 숨기지만 id 를 쿼리에 그대로 넣어 조건 참/거짓이 결과에 반영됨.
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if blindTrue(r.URL.Query().Get("id")) { // 취약: 주입된 불린이 결과를 바꿈
			fmt.Fprint(w, "<html><body><h2>User found</h2><p>이름: Alice · 등급: gold</p></body></html>")
		} else {
			fmt.Fprint(w, "<html><body><h2>No user found</h2></body></html>")
		}
	})

	// 안전 조회 — 정상(대조군): id 를 정수로 파싱(파라미터화). 주입 문자열은 항상 미일치.
	mux.HandleFunc("/user-safe", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "1" { // 정상: 리터럴 비교 → 주입 무효
			fmt.Fprint(w, "<html><body><h2>User found</h2><p>이름: Alice</p></body></html>")
		} else {
			fmt.Fprint(w, "<html><body><h2>No user found</h2></body></html>")
		}
	})

	// 경로 순회 — 취약: file 파라미터를 정규화·화이트리스트 없이 그대로 읽어 반환.
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		file := strings.ToLower(r.URL.Query().Get("file"))
		switch { // 취약: 순회 시퀀스가 실제 시스템 파일로 도달
		case strings.Contains(file, "passwd"):
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
		case strings.Contains(file, "win.ini"):
			fmt.Fprint(w, "[extensions]\n[fonts]\nfor 16-bit app support\n")
		default:
			fmt.Fprintf(w, "file: %s (not found)", file)
		}
	})

	// 오픈 리다이렉트 — 취약: url 파라미터를 외부 검증 없이 그대로 302 목적지로.
	mux.HandleFunc("/go", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound) // 취약: 외부 URL 무검증
	})

	// 파일 업로드 — 취약: 확장자·타입 검증 없이 아무 파일이나 수용.
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if whoami(r) == "" {
			http.Error(w, "401 인증 필요", http.StatusUnauthorized)
			return
		}
		_, hdr, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "400 파일 없음", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "업로드 완료: %s", hdr.Filename) // 취약: .php 도 수용
	})

	// 안전 업로드 — 정상(대조군): 위험 확장자 거부.
	mux.HandleFunc("/upload-safe", func(w http.ResponseWriter, r *http.Request) {
		if whoami(r) == "" {
			http.Error(w, "401 인증 필요", http.StatusUnauthorized)
			return
		}
		_, hdr, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "400 파일 없음", http.StatusBadRequest)
			return
		}
		bad := map[string]bool{".php": true, ".jsp": true, ".asp": true, ".aspx": true, ".exe": true, ".sh": true, ".html": true}
		if bad[strings.ToLower(filepath.Ext(hdr.Filename))] { // 정상: 위험 확장자 차단
			http.Error(w, "403 허용되지 않는 확장자", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, "업로드 완료: %s", hdr.Filename)
	})

	// 송금 실행 — 취약(CSRF): 세션만 확인하고 anti-CSRF 토큰이 없어 위조 요청에 취약.
	mux.HandleFunc("/transfer", func(w http.ResponseWriter, r *http.Request) {
		if whoami(r) == "" {
			http.Error(w, "401 인증 필요", http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm() // amount, to (토큰 검증 없음)
		fmt.Fprintf(w, "이체 완료: %s → %s", r.FormValue("amount"), r.FormValue("to"))
	})

	// 이메일 변경 — 정상(대조군): anti-CSRF 토큰(csrf_token) 검증. 토큰 없으면 거부.
	mux.HandleFunc("/change-email", func(w http.ResponseWriter, r *http.Request) {
		if whoami(r) == "" {
			http.Error(w, "401 인증 필요", http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("csrf_token") == "" { // 정상: 토큰 없으면 거부
			http.Error(w, "403 CSRF 토큰 없음", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, "이메일 변경 완료: %s", r.FormValue("email"))
	})

	// 안전 리다이렉트 — 정상(대조군): 같은 오리진 경로만 허용, 외부 호스트 거부.
	mux.HandleFunc("/safe-go", func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("url")
		if strings.HasPrefix(dest, "/") && !strings.HasPrefix(dest, "//") { // 정상: 내부 경로만
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
		http.Error(w, "400 유효하지 않은 리다이렉트", http.StatusBadRequest) // 외부 URL 거부
	})

	log.Printf("[VULNAPP] 취약 테스트 앱 시작: http://%s (데모/테스트 전용)", *addr)
	log.Fatal(http.ListenAndServe(*addr, noSecurityHeaders(mux)))
}

// noSecurityHeaders — 보안 헤더를 일부러 붙이지 않음(누락 탐지 자극). 기본 Go 서버가 이미 없음.
func noSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r) // CSP/HSTS/X-Frame-Options 등 미설정
	})
}
