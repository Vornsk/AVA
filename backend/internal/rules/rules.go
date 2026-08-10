// Package rules — 전송 전 Rule 판단 스테이지 (FR-2.2).
// 스코프를 통과한 요청이라도, 위험/파괴적 요청은 결정론적 룰로 전송 전 차단해
// 가용성을 보호한다 (예: logout·delete·admin·결제확정).
//
//	· 기본 룰셋 내장 (진단자 오버라이드는 추후 config에서)
//	· Rule 스테이지 뒤에 LLM 스테이지가 붙을 자리 (Rule→LLM 파이프라인)
package rules

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Rule — 룰 정의(직렬화·조회·설정용).
type Rule struct {
	Name        string   `json:"name" yaml:"name"`
	Action      string   `json:"action" yaml:"action"`                       // "block" | "allow"
	Methods     []string `json:"methods" yaml:"methods,omitempty"`           // 비면 모든 메서드
	PathPattern string   `json:"path_pattern" yaml:"path_pattern,omitempty"` // path 정규식(대소문자 무시). 비면 모든 경로
	Reason      string   `json:"reason" yaml:"reason"`
}

// Decision — 판단 결과. Action: "block" | "allow" | "llm" | "" (매칭 없음 → 통과).
type Decision struct {
	Action string
	Rule   string
	Reason string
}

type compiled struct {
	def     Rule
	methods map[string]bool
	re      *regexp.Regexp // nil = 모든 경로
}

var (
	mu      sync.RWMutex
	ruleset []compiled
	adopted []Rule // HITL로 승인·채택된 룰 (영속 대상)
)

const adoptedFile = "rules.adopted.json"

// 기본 룰셋: 파괴적/위험 요청 차단 (가용성 보호). 문서 FR-2.2 예시 기반.
var defaultRules = []Rule{
	{Name: "block-logout", Action: "block", PathPattern: `(?i)(logout|log-out|logoff|signout|sign-out)`, Reason: "세션 종료 방지(가용성)"},
	{Name: "block-delete-method", Action: "block", Methods: []string{"DELETE"}, Reason: "파괴적 DELETE 메서드 차단"},
	{Name: "block-delete-path", Action: "block", PathPattern: `(?i)(delete|remove|drop|destroy|purge)`, Reason: "삭제성 요청 차단"},
	{Name: "block-admin", Action: "block", PathPattern: `(?i)/admin(istrator)?(/|$)|/manage(/|$)`, Reason: "관리자 기능 보호"},
	{Name: "block-payment", Action: "block", PathPattern: `(?i)(pay|order|checkout)/(confirm|complete)|withdraw|remit|결제확정|이체|송금`, Reason: "결제/이체 확정 차단"},
	// 룰로 딱 잘라 못 정하는 상태변경 요청은 LLM 스테이지로 위임 (Rule→LLM).
	{Name: "llm-review-writes", Action: "llm", Methods: []string{"POST", "PUT", "PATCH"}, Reason: "상태변경 요청 — LLM 위험 판단"},
}

func init() {
	Load(defaultRules)
}

// Defaults — 내장 기본 룰셋의 복사본 (config 템플릿 생성용).
func Defaults() []Rule {
	out := make([]Rule, len(defaultRules))
	copy(out, defaultRules)
	return out
}

// compile — 룰 1건을 매칭 가능한 형태로 변환. PathPattern 이 잘못된 정규식이면 실패(ok=false).
func compile(d Rule) (compiled, bool) {
	c := compiled{def: d}
	if len(d.Methods) > 0 {
		c.methods = map[string]bool{}
		for _, m := range d.Methods {
			c.methods[strings.ToUpper(m)] = true
		}
	}
	if d.PathPattern != "" {
		re, err := regexp.Compile(d.PathPattern)
		if err != nil {
			return compiled{}, false
		}
		c.re = re
	}
	return c, true
}

// Load — 룰 정의를 컴파일해 적용. (추후 config 로드에서 재사용)
func Load(defs []Rule) {
	cs := make([]compiled, 0, len(defs))
	for _, d := range defs {
		if c, ok := compile(d); ok {
			cs = append(cs, c)
		}
	}
	mu.Lock()
	ruleset = cs
	mu.Unlock()
}

// Add — 승인된 룰 1건을 활성 룰셋 앞에 추가하고 영속화(FR-2.2 HITL 채택, rule:promote).
// 앞에 두어 기본 가드레일/LLM 위임보다 우선 적용된다. 반환값: 채택 성공 여부.
func Add(r Rule) bool {
	c, ok := compile(r)
	if !ok {
		return false
	}
	mu.Lock()
	for _, a := range adopted {
		if a.Name == r.Name { // 동일 이름 중복 채택 방지
			mu.Unlock()
			return false
		}
	}
	ruleset = append([]compiled{c}, ruleset...)
	adopted = append(adopted, r)
	snap := append([]Rule(nil), adopted...)
	mu.Unlock()
	persistAdopted(snap)
	return true
}

// Adopted — 지금까지 채택된 룰 목록(조회용).
func Adopted() []Rule {
	mu.RLock()
	defer mu.RUnlock()
	return append([]Rule(nil), adopted...)
}

// LoadAdopted — 재시작 시 rules.adopted.json 의 채택 룰을 다시 적용한다(startup에서 Load 이후 호출).
func LoadAdopted() {
	data, err := os.ReadFile(adoptedFile)
	if err != nil {
		return
	}
	var defs []Rule
	if json.Unmarshal(data, &defs) != nil {
		return
	}
	for _, d := range defs {
		Add(d)
	}
}

func persistAdopted(snapshot []Rule) {
	data, _ := json.MarshalIndent(snapshot, "", "  ")
	_ = os.WriteFile(adoptedFile, data, 0644)
}

// Evaluate — 첫 매칭 룰로 판단. block이면 차단, allow면 즉시 통과.
func Evaluate(method, path string) Decision {
	mu.RLock()
	defer mu.RUnlock()
	for _, c := range ruleset {
		if c.methods != nil && !c.methods[strings.ToUpper(method)] {
			continue
		}
		if c.re != nil && !c.re.MatchString(path) {
			continue
		}
		return Decision{Action: c.def.Action, Rule: c.def.Name, Reason: c.def.Reason}
	}
	return Decision{Action: ""} // 매칭 없음 → 통과
}

// SetReconAllow — recon(GET/HEAD) 허용 경로를 guardrail 룰 앞에 끼워 넣는다.
// block-admin 처럼 가용성 보호 룰에 막히는 경로라도, 분석가가 접근통제 점검을 위해
// 명시적으로 능동 recon 을 허용할 때 사용. 읽기(GET/HEAD)만 허용하므로
// 파괴적 메서드(POST/DELETE 등)는 여전히 뒤의 block 룰이 막는다(가드레일 유지).
func SetReconAllow(patterns []string) {
	if len(patterns) == 0 {
		return
	}
	front := make([]compiled, 0, len(patterns))
	for _, p := range patterns {
		front = append(front, compiled{
			def: Rule{
				Name: "recon-allow", Action: "allow",
				Methods: []string{"GET", "HEAD"}, PathPattern: p,
				Reason: "recon 허용(접근통제 점검)",
			},
			methods: map[string]bool{"GET": true, "HEAD": true},
			re:      regexp.MustCompile(p),
		})
	}
	mu.Lock()
	ruleset = append(front, ruleset...)
	mu.Unlock()
}

// Snapshot — 현재 룰 목록(조회용, MCP list_rules).
func Snapshot() []Rule {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Rule, len(ruleset))
	for i, c := range ruleset {
		out[i] = c.def
	}
	return out
}
