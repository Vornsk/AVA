package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// MockProvider — 오프라인 기본 프로바이더 (API 키 불필요).
// 실제 LLM 대신 결정론적 휴리스틱으로 응답을 흉내낸다.
// system 프롬프트로 작업을 구분: 판단 verdict 계약=판단, "endpoint-classifier"=의미분류, "triage"=오탐검토.
// 판단을 먼저 확인하는 이유: 판단 프롬프트가 프리셋·커스텀으로 바뀔 수 있어(이슈 #53)
// 문구 키워드 대신 고정된 출력 계약(verdictContract)으로 식별해야 오라우팅이 없다.
type MockProvider struct{}

func (MockProvider) Name() string { return "mock" }

var mockRiskyParams = map[string]bool{
	"amount": true, "account": true, "card": true, "transfer": true,
	"remit": true, "balance": true, "wire": true, "iban": true,
}

func (MockProvider) Complete(_ context.Context, system, user string) (string, error) {
	judgeTask := strings.Contains(system, verdictContract)
	// 엔드포인트 의미 분류 (이슈 #41) — 경로·키 키워드로 라벨 흉내 (실제 LLM 대체 데모).
	if !judgeTask && strings.Contains(system, "endpoint-classifier") {
		low := strings.ToLower(user)
		var labels []string
		add := func(cond bool, l string) {
			if cond {
				labels = append(labels, l)
			}
		}
		hasAny := func(subs ...string) bool {
			for _, s := range subs {
				if strings.Contains(low, s) {
					return true
				}
			}
			return false
		}
		add(hasAny("login", "auth", "token", "password", "session", "oauth"), "auth")
		add(hasAny("pay", "checkout", "order", "billing", "card", "amount", "wallet"), "payment")
		add(hasAny("upload", "file", "import", "attachment"), "upload")
		add(hasAny("admin", "manage", "console", "backoffice", "internal"), "admin")
		add(hasAny("profile", "account", "customer", "kyc", "email", "ssn", "phone"), "pii")
		add(hasAny("search", "query", "keyword", "lookup"), "search")
		if len(labels) == 0 {
			labels = []string{"other"}
		}
		b, _ := json.Marshal(map[string][]string{"labels": labels})
		return string(b), nil
	}
	// 엔드포인트별 탐지기 추천(recommend, HITL 스캔 계획) — 파라미터·라벨 유무로 휴리스틱 추천.
	if !judgeTask && strings.Contains(system, "security-scan planner") {
		return mockRecommendDetectors(user), nil
	}
	// 오탐 검토(Review) — 응답 증적으로 휴리스틱 판정 (실제 LLM 대체 데모)
	if !judgeTask && strings.Contains(system, "triage") {
		low := strings.ToLower(user)
		verdict := "uncertain"
		switch {
		// 렌더링되지 않는 미디어타입에 반사된 값은 브라우저가 실행하지 않는다 (이슈 #54).
		// #49 벤치의 오탐 5건이 전부 이 유형이었는데, mock 이 Content-Type 을 안 봐서
		// 한 건도 못 걸렀다. detector 와 같은 맹점을 공유하던 자리다.
		case isXSSFinding(low) && nonRenderingType(low):
			verdict = "false_positive"
		case strings.Contains(low, "&lt;") || strings.Contains(low, "&gt;") ||
			strings.Contains(low, "textarea") || strings.Contains(low, "<!--"):
			verdict = "false_positive" // 인코딩/비실행 컨텍스트 반사 → 오탐
		case strings.Contains(user, "주민등록번호") || strings.Contains(user, "카드") ||
			strings.Contains(low, "sql syntax") || strings.Contains(low, "root:") ||
			strings.Contains(low, "location:") || strings.Contains(low, "severity=high"):
			verdict = "real" // 응답 증적이 취약을 확증
		}
		reason := map[string]string{
			"false_positive": "응답이 비렌더링 미디어타입이거나 인코딩/비실행 컨텍스트로 실행 불가",
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

// mockRecommendDetectors — recommend.recommendUser 가 만든 JSON 배열을 파싱해 대상마다
// 파라미터·라벨 유무로 탐지기 id를 휴리스틱 배정한다(실제 LLM 대체 데모). 목적은 정확성이
// 아니라 오프라인 기본 설정에서도 "llm 성공 경로"(수동 검증)를 실제로 볼 수 있게 하는 것.
func mockRecommendDetectors(user string) string {
	var eps []struct {
		Key    string `json:"key"`
		Method string `json:"method"`
		Params []struct {
			Name string `json:"name"`
		} `json:"params"`
		Labels []string `json:"labels"`
		Auth   bool     `json:"auth"`
	}
	if json.Unmarshal([]byte(user), &eps) != nil {
		return `{"items":[]}`
	}
	type outItem struct {
		Key       string   `json:"key"`
		Detectors []string `json:"detectors"`
	}
	items := make([]outItem, 0, len(eps))
	for _, e := range eps {
		dets := []string{"sec-headers", "sensitive-data", "cookie-security", "http-method"}
		if len(e.Params) > 0 {
			dets = append(dets, "sqli", "sqli-blind", "reflected-input", "path-traversal", "open-redirect")
		}
		hasLabel := func(l string) bool {
			for _, x := range e.Labels {
				if x == l {
					return true
				}
			}
			return false
		}
		if e.Auth || hasLabel("auth") {
			dets = append(dets, "idor", "privesc")
		}
		switch strings.ToUpper(e.Method) {
		case "POST", "PUT", "PATCH", "DELETE":
			dets = append(dets, "csrf")
		}
		items = append(items, outItem{Key: e.Key, Detectors: dets})
	}
	b, _ := json.Marshal(map[string]any{"items": items})
	return string(b)
}

// isXSSFinding / nonRenderingType — XSS 계열 발견인데 응답이 렌더링되지 않는 미디어타입인가
// (이슈 #54). user 프롬프트의 detector=·content_type= 줄을 본다.
func isXSSFinding(lowerUser string) bool {
	for _, d := range []string{"detector=reflected-input", "detector=stored-xss", "detector=dom-xss"} {
		if strings.Contains(lowerUser, d) {
			return true
		}
	}
	return false
}

func nonRenderingType(lowerUser string) bool {
	i := strings.Index(lowerUser, "content_type=")
	if i < 0 {
		return false
	}
	line := lowerUser[i+len("content_type="):]
	if j := strings.IndexByte(line, '\n'); j >= 0 {
		line = line[:j]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return false // 미상은 판단 근거가 아니다
	}
	for _, render := range []string{"text/html", "application/xhtml+xml", "image/svg+xml"} {
		if strings.HasPrefix(line, render) {
			return false
		}
	}
	return true
}
