// Package masking — 민감값이 로그·저장 경계를 넘을 때 마스킹. (§8, FR-2.3)
//
//	· 패턴 기반: 주민등록번호, 카드번호, JWT
//	· 키 기반  : password/token/secret/api_key/rrn 등 민감 파라미터명의 값
package masking

import "regexp"

var (
	// 패턴 기반: 값 생김새로 탐지
	reRRN  = regexp.MustCompile(`\d{6}-\d{7}`)             // 주민등록번호
	reCard = regexp.MustCompile(`\d{4}-\d{4}-\d{4}-\d{4}`) // 카드번호
	reJWT  = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

	// 키 기반: 이 이름을 가진 파라미터/쿠키의 값을 가림 (key=value 형태)
	reKV = regexp.MustCompile(
		`(?i)(password|passwd|pwd|token|access_token|secret|api_?key|authorization|ssn|rrn|cardno?|session(id)?|jsessionid|phpsessid|sid|csrf|xsrf)=([^&\s]*)`)
)

// Mask: 문자열에서 민감값을 마스킹. URL·로그 라인 등 경계 출력에 적용.
func Mask(s string) string {
	s = reRRN.ReplaceAllString(s, "******-*******")
	s = reCard.ReplaceAllString(s, "****-****-****-****")
	s = reJWT.ReplaceAllString(s, "***JWT***")
	s = reKV.ReplaceAllString(s, "${1}=***")
	return s
}

// Sample: 파라미터 값의 안전한 샘플. 민감하면 ***, 아니면 짧게 노출(§3 샘플값 마스킹).
func Sample(name, value string) string {
	if value == "" {
		return ""
	}
	kv := name + "=" + value
	if Mask(kv) != kv {
		return "***" // 키 또는 값이 마스킹 대상 = 민감
	}
	const max = 24
	if len(value) > max {
		return value[:max] + "…"
	}
	return value
}
