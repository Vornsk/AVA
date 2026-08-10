package llm

import (
	"context"
	"fmt"
	"strings"
)

// MockProvider — 오프라인 기본 프로바이더 (API 키 불필요).
// 실제 LLM 대신 결정론적 휴리스틱으로 응답을 흉내낸다.
// system 프롬프트로 작업을 구분: "gatekeeper"=판단, "triage"=오탐검토.
type MockProvider struct{}

func (MockProvider) Name() string { return "mock" }

var mockRiskyParams = map[string]bool{
	"amount": true, "account": true, "card": true, "transfer": true,
	"remit": true, "balance": true, "wire": true, "iban": true,
}

func (MockProvider) Complete(_ context.Context, system, user string) (string, error) {
	// 오탐 검토(Review) — 응답 증적으로 휴리스틱 판정 (실제 LLM 대체 데모)
	if strings.Contains(system, "triage") {
		low := strings.ToLower(user)
		verdict := "uncertain"
		switch {
		case strings.Contains(low, "&lt;") || strings.Contains(low, "&gt;") ||
			strings.Contains(low, "textarea") || strings.Contains(low, "<!--"):
			verdict = "false_positive" // 인코딩/비실행 컨텍스트 반사 → 오탐
		case strings.Contains(user, "주민등록번호") || strings.Contains(user, "카드") ||
			strings.Contains(low, "sql syntax") || strings.Contains(low, "root:") ||
			strings.Contains(low, "location:") || strings.Contains(low, "severity=high"):
			verdict = "real" // 응답 증적이 취약을 확증
		}
		reason := map[string]string{
			"false_positive": "응답이 인코딩/비실행 컨텍스트로 실행 불가",
			"real":           "응답 증적이 취약을 확증",
			"uncertain":      "증적만으로 판단 불충분 — 수동 검토 권장",
		}[verdict]
		return fmt.Sprintf(`{"verdict":%q,"reason":%q,"remediation":"입력 검증·출력 인코딩·접근통제 점검"}`, verdict, reason), nil
	}
	// 판단(Judge): user의 param_keys 에 금융성 파라미터가 보이면 차단
	for k := range mockRiskyParams {
		if strings.Contains(user, k) {
			return fmt.Sprintf(`{"allow":false,"reason":"금융성 파라미터(%s) 감지","confidence":0.8}`, k), nil
		}
	}
	return `{"allow":true,"reason":"위험 신호 없음","confidence":0.6}`, nil
}
