// Package llm — LLM 판단 스테이지 (문서 §5.2 LLM 스테이지, §7 게이트웨이).
// Rule로 애매한 요청만 LLM에 위임한다. 프로바이더는 교체 가능(§2.1).
//
//	· 입력은 토큰 최소화 (FR-2.3): method+정규화path+파라미터키+content-type+힌트. 값 없음.
//	· 동일 입력은 캐시(dedup)로 재질의 방지 (FR-2.3).
//	· 모든 판단을 LLMDecision으로 로깅 (§3, §5.6 룰 이관 입력).
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
)

// New — config 값으로 프로바이더 생성 (교체 지점 한 곳). 새 프로바이더는 여기만 추가.
//
//	provider: mock | ollama | anthropic | openai
//	openai 는 OpenAI 호환 API(엔드포인트 교체로 OpenAI·xAI Grok·Groq·vLLM·LM Studio 등 커버).
func New(provider, model, endpoint, apiKey string) Provider {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "ollama":
		return NewOllama(model, endpoint)
	case "anthropic":
		return NewAnthropic(apiKey, model, endpoint)
	case "openai":
		return NewOpenAI(apiKey, model, endpoint)
	case "mock", "":
		return MockProvider{}
	default:
		log.Printf("알 수 없는 LLM 프로바이더 %q → mock 사용", provider)
		return MockProvider{}
	}
}

// promptUser — 토큰최소화 입력을 프로바이더 공용 user 프롬프트로. (anthropic/ollama/openai 공유)
func promptUser(in JudgeInput) string {
	return fmt.Sprintf("method=%s\npath=%s\nparam_keys=%s\ncontent_type=%s\nhint=%s",
		in.Method, in.Path, strings.Join(in.ParamKeys, ","), in.ContentType, in.Hint)
}

// JudgeInput — 토큰 최소화된 판단 입력. 원문/파라미터 값은 포함하지 않는다.
type JudgeInput struct {
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	ParamKeys   []string `json:"param_keys"`
	ContentType string   `json:"content_type"`
	Hint        string   `json:"hint"`
}

// Verdict — LLM 판단 결과.
type Verdict struct {
	Allow      bool    `json:"allow"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
	Provider   string  `json:"provider"`
	Model      string  `json:"model"`
}

// Provider — LLM 프로바이더 추상화 (mock/anthropic/ollama/openai/… 교체 가능).
// 범용 Complete만 구현하면 되고, 판단(Judge)·오탐검토(Review)는 이 패키지가 조립한다.
type Provider interface {
	Name() string
	// Complete — system+user 프롬프트로 텍스트(보통 JSON) 응답 반환.
	Complete(ctx context.Context, system, user string) (string, error)
}

// Decision — 판단 로그 항목 (LLMDecision, §3).
type Decision struct {
	ID      int        `json:"id"`
	Input   JudgeInput `json:"input"`
	Verdict Verdict    `json:"verdict"`
	Cached  bool       `json:"cached"`
}

var (
	mu        sync.Mutex
	provider  Provider
	cache     = map[string]Verdict{}
	decisions []Decision
	seq       int
)

// SetProvider — 활성 프로바이더 지정 (기동 시 config 기반).
func SetProvider(p Provider) {
	mu.Lock()
	provider = p
	mu.Unlock()
}

// ProviderName — 현재 활성 프로바이더 이름(없으면 "none").
func ProviderName() string {
	mu.Lock()
	defer mu.Unlock()
	if provider == nil {
		return "none"
	}
	return provider.Name()
}

// Available — 활성 LLM 프로바이더가 있는가. 호출자가 LLM 경로를 탈지 결정할 때 쓴다 (이슈 #41).
func Available() bool {
	mu.Lock()
	defer mu.Unlock()
	return provider != nil
}

// Complete — 활성 프로바이더로 범용 완성 요청. 프로바이더가 없으면 ErrNoProvider.
// Judge/Review 외의 용도(예: 정찰 의미 분류 #41)가 프로바이더를 직접 재사용하기 위한 진입점.
func Complete(ctx context.Context, system, user string) (string, error) {
	mu.Lock()
	p := provider
	mu.Unlock()
	if p == nil {
		return "", ErrNoProvider
	}
	return p.Complete(ctx, system, user)
}

// ErrNoProvider — 활성 LLM 프로바이더가 없다.
var ErrNoProvider = errors.New("활성 LLM 프로바이더 없음")

func sig(in JudgeInput) string {
	keys := append([]string(nil), in.ParamKeys...)
	sort.Strings(keys)
	return in.Method + " " + in.Path + " [" + strings.Join(keys, ",") + "] " + in.ContentType
}

// Judge — 캐시 확인 → 프로바이더 호출 → 로깅. 프로바이더 오류 시 가용성 위해 기본 허용.
func Judge(ctx context.Context, in JudgeInput) Verdict {
	key := sig(in)

	mu.Lock()
	p := provider
	if v, ok := cache[key]; ok {
		seq++
		decisions = appendCapped(decisions, Decision{ID: seq, Input: in, Verdict: v, Cached: true})
		mu.Unlock()
		return v
	}
	mu.Unlock()

	var v Verdict
	if p == nil {
		v = Verdict{Allow: true, Reason: "프로바이더 없음 — 기본 허용", Provider: "none"}
	} else if content, err := p.Complete(ctx, sysPrompt, promptUser(in)); err != nil {
		v = Verdict{Allow: true, Reason: "프로바이더 오류(" + err.Error() + ") — 가용성 위해 기본 허용", Provider: p.Name()}
	} else {
		var vj struct {
			Allow      bool    `json:"allow"`
			Reason     string  `json:"reason"`
			Confidence float64 `json:"confidence"`
		}
		if e := json.Unmarshal([]byte(extractJSON(content)), &vj); e != nil {
			v = Verdict{Allow: true, Reason: "verdict 파싱 실패 — 기본 허용", Provider: p.Name()}
		} else {
			v = Verdict{Allow: vj.Allow, Reason: vj.Reason, Confidence: normConf(vj.Confidence), Provider: p.Name()}
		}
	}

	mu.Lock()
	cache[key] = v
	seq++
	decisions = appendCapped(decisions, Decision{ID: seq, Input: in, Verdict: v, Cached: false})
	mu.Unlock()
	return v
}

// normConf — 신뢰도를 0..1 로 정규화. 모델이 10/100 스케일로 반환하는 경우 보정.
func normConf(c float64) float64 {
	for c > 1 {
		c /= 10
	}
	if c < 0 {
		c = 0
	}
	return c
}

func appendCapped(list []Decision, d Decision) []Decision {
	list = append(list, d)
	if len(list) > 200 {
		list = list[len(list)-200:]
	}
	return list
}

// Decisions — 판단 로그 스냅샷 (MCP llm_decisions).
func Decisions() []Decision {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Decision, len(decisions))
	copy(out, decisions)
	return out
}

// ── 오탐 검토 / 조치문구 (FR-3.3, §8 HITL) ────────────────────────

// ReviewInput — 진단 finding 검토 입력 (마스킹된 증적만). 실제 요청/응답 증적으로 문맥 판단.
type ReviewInput struct {
	Vuln     string
	Severity string
	Method   string
	Path     string
	Param    string
	Detector string
	Evidence string
	Request  string // 재현 요청 (FR-4.2, 마스킹)
	Response string // 증명 응답 스니펫 (FR-4.2, 마스킹)
	RespCode int
}

// ReviewResult — LLM 오탐 판정 + 조치문구.
type ReviewResult struct {
	Verdict     string `json:"verdict"` // real | false_positive | uncertain
	Reason      string `json:"reason"`
	Remediation string `json:"remediation"` // 조치문구
	Provider    string `json:"provider"`
}

// triage 라는 단어를 포함해 mock 프로바이더가 작업을 구분하게 한다.
const reviewSysPrompt = "You are a security triage assistant for an authorized web assessment. " +
	"An automated scanner produced a finding using a heuristic that can misfire; your job is to catch false positives. " +
	"Given the finding, the reproduction request, and the masked response evidence, decide whether it is a REAL vulnerability or a FALSE POSITIVE. " +
	"Reason about context: reflected input is XSS only if it lands unencoded in an executable HTML position; a reflected value inside a comment/textarea/attribute or HTML-encoded is a false positive; " +
	"a DB error string confirms SQLi; a 3xx Location to an external host confirms open redirect; missing anti-CSRF token is only medium confidence. " +
	"Reply with ONLY compact JSON: {\"verdict\":\"real|false_positive|uncertain\",\"reason\":string,\"remediation\":string}."

// Review — finding을 LLM으로 오탐 판정하고 조치문구를 생성 (FR-3.3). 오류/무프로바이더 시 uncertain.
func Review(ctx context.Context, in ReviewInput) ReviewResult {
	mu.Lock()
	p := provider
	mu.Unlock()
	if p == nil {
		return ReviewResult{Verdict: "uncertain", Reason: "프로바이더 없음", Provider: "none"}
	}
	user := fmt.Sprintf("vuln=%s\nseverity=%s\nmethod=%s\npath=%s\nparam=%s\ndetector=%s\nsummary=%s\nrequest=%s\nresponse(HTTP %d)=%s",
		in.Vuln, in.Severity, in.Method, in.Path, in.Param, in.Detector, in.Evidence, in.Request, in.RespCode, in.Response)

	content, err := p.Complete(ctx, reviewSysPrompt, user)
	if err != nil {
		return ReviewResult{Verdict: "uncertain", Reason: "프로바이더 오류: " + err.Error(), Provider: p.Name()}
	}
	var rr ReviewResult
	if e := json.Unmarshal([]byte(extractJSON(content)), &rr); e != nil {
		return ReviewResult{Verdict: "uncertain", Reason: "review 파싱 실패", Provider: p.Name()}
	}
	rr.Provider = p.Name()
	return rr
}
