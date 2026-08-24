// Package advisor — 룰 이관 제안 (§5.6, rule-advisor 모듈).
// LLM 판단 로그(FR-6.1)를 정규화 시그니처별로 군집화해, 빈도·일관성·신뢰도가 높고
// 구체 피처(method·path·param·content-type)로 설명 가능한 패턴을 룰 이관 후보로 제안한다(FR-6.2).
// 후보마다 초안 룰·근거 샘플·예상 절감·오탐 경고를 함께 낸다(FR-6.3).
// **자동 이관 금지 — 진단자 검토·승인 필수(HITL, §8).** 승격/섀도검증은 후속 단계.
package advisor

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"proxypoc/internal/llm"
	"proxypoc/internal/rules"
)

// Candidate — 룰 이관 후보 (§3 RulePromotionCandidate).
type Candidate struct {
	Signature     string     `json:"signature"` // 정규화 시그니처
	Method        string     `json:"method"`
	Path          string     `json:"path"`
	Verdict       string     `json:"verdict"`     // block | allow (다수결)
	Hits          int        `json:"hits"`        // 적중수(빈도)
	Consistency   float64    `json:"consistency"` // 일관성 0..1 (다수 verdict 비율)
	AvgConfidence float64    `json:"avg_confidence"`
	Deterministic bool       `json:"deterministic"` // 구체 피처로 설명 가능
	Samples       []int      `json:"samples"`       // 근거 케이스 (decision id)
	EstSavings    int        `json:"est_savings"`   // 예상 절감 (재질의 회피 수)
	Warning       string     `json:"warning,omitempty"`
	Status        string     `json:"status"`     // 제안 (HITL 대기)
	DraftRule     rules.Rule `json:"draft_rule"` // 초안 룰 (YAML/DSL)
}

func signature(d llm.Decision) string {
	keys := append([]string(nil), d.Input.ParamKeys...)
	sort.Strings(keys)
	return d.Input.Method + " " + d.Input.Path + " [" + strings.Join(keys, ",") + "] " + d.Input.ContentType
}

// Analyze — 판단 로그에서 이관 후보를 도출한다(순수 함수, 테스트 용이).
//
//	minHits        : 최소 빈도 (이보다 적으면 제외)
//	minConsistency : 최소 일관성 (다수 verdict 비율)
func Analyze(decisions []llm.Decision, minHits int, minConsistency float64) []Candidate {
	return analyzeLang(decisions, minHits, minConsistency, "ko")
}

// analyzeLang — 로케일별 후보 도출. Reason/Warning 자유서술을 lang 으로 생성(#18).
func analyzeLang(decisions []llm.Decision, minHits int, minConsistency float64, lang string) []Candidate {
	groups := map[string][]llm.Decision{}
	order := []string{}
	for _, d := range decisions {
		s := signature(d)
		if _, ok := groups[s]; !ok {
			order = append(order, s)
		}
		groups[s] = append(groups[s], d)
	}

	var out []Candidate
	for _, s := range order {
		ds := groups[s]
		hits := len(ds)
		if hits < minHits {
			continue
		}
		block, allow := 0, 0
		var confSum float64
		samples := make([]int, 0, hits)
		models := map[string]bool{}
		prompts := map[string]bool{} // 판단 프롬프트 정책 (이슈 #53)
		for _, d := range ds {
			if d.Verdict.Allow {
				allow++
			} else {
				block++
			}
			confSum += d.Verdict.Confidence
			samples = append(samples, d.ID)
			models[d.Verdict.Model] = true
			prompts[d.Verdict.Prompt] = true
		}
		maj, verdict := block, "block"
		if allow > block {
			maj, verdict = allow, "allow"
		}
		consistency := float64(maj) / float64(hits)
		if consistency < minConsistency {
			continue // 순수 의미론적/불안정 판단 — 이관 부적합(FR-6.2)
		}

		d0 := ds[0]
		if d0.Input.Path == "" {
			continue // path 로 설명 불가 → 결정론적 근거 없음
		}
		pathPat := "(?i)^" + regexp.QuoteMeta(d0.Input.Path) + "$"
		methods := []string(nil)
		if d0.Input.Method != "" {
			methods = []string{d0.Input.Method}
		}

		c := Candidate{
			Signature: s, Method: d0.Input.Method, Path: d0.Input.Path,
			Verdict: verdict, Hits: hits, Consistency: consistency,
			AvgConfidence: confSum / float64(hits),
			Deterministic: true, // 시그니처가 method·path·param·content-type 로 구성됨
			Samples:       samples, EstSavings: hits, Status: "제안",
			DraftRule: rules.Rule{
				Name:        "advisor:" + verdict + ":" + d0.Input.Path,
				Action:      verdict,
				Methods:     methods,
				PathPattern: pathPat,
				Reason:      reasonText(lang, consistency, hits),
			},
		}
		var warns []string
		if consistency < 1.0 {
			warns = append(warns, warnDissent(lang, hits-maj))
		}
		if len(models) > 1 {
			warns = append(warns, warnMixedModel(lang))
		}
		if len(prompts) > 1 { // 보수성이 다른 정책의 판정이 섞였다 — 룰은 전역이라 그대로 이관하면 안 된다 (이슈 #53)
			warns = append(warns, warnMixedPrompt(lang, sortedKeys(prompts)))
		}
		if c.AvgConfidence < 0.7 {
			warns = append(warns, warnLowConf(lang, c.AvgConfidence))
		}
		c.Warning = strings.Join(warns, " / ")
		out = append(out, c)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Consistency > out[j].Consistency
	})
	return out
}

// Candidates — 현재 판단 로그로 기본 임계(빈도≥2, 일관성≥70%) 후보 도출(한국어).
func Candidates() []Candidate {
	return CandidatesLang("ko")
}

// CandidatesLang — 로케일별 후보 도출 (Reason/Warning 문구 로케일화, #18).
func CandidatesLang(lang string) []Candidate {
	return analyzeLang(llm.Decisions(), 2, 0.7, lang)
}

// ── 후보 서술 문구 로케일 (#18) ──
func reasonText(lang string, consistency float64, hits int) string {
	if lang == "en" {
		return fmt.Sprintf("LLM decision migration candidate (consistency %.0f%%, %d hits)", consistency*100, hits)
	}
	return fmt.Sprintf("LLM 판단 이관 후보 (일관성 %.0f%%, %d건)", consistency*100, hits)
}

func warnDissent(lang string, dissent int) string {
	if lang == "en" {
		return fmt.Sprintf("%d dissenting verdicts — false-positive risk, shadow-verification recommended (FR-6.4)", dissent)
	}
	return fmt.Sprintf("반대 판정 %d건 — 오탐 위험, 섀도검증 권장(FR-6.4)", dissent)
}

func warnMixedModel(lang string) string {
	if lang == "en" {
		return "Mixed model versions — re-verify stability"
	}
	return "모델 버전 혼재 — 안정성 재확인"
}

// warnMixedPrompt — 서로 다른 판단 프롬프트 정책의 판정이 한 시그니처에 섞였을 때 (이슈 #53).
// 채택된 룰은 프로젝트 공용이므로, 보수성이 다른 정책의 판정을 뭉쳐 이관하면 정책이 조용히 새어나간다.
func warnMixedPrompt(lang string, ids []string) string {
	if lang == "en" {
		return "Mixed judgment prompt policies (" + strings.Join(ids, ", ") + ") — rules are global; re-verify under one policy"
	}
	return "판단 프롬프트 정책 혼재(" + strings.Join(ids, ", ") + ") — 룰은 전역이므로 한 정책으로 재확인 필요"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k == "" {
			k = "unknown"
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func warnLowConf(lang string, avg float64) string {
	if lang == "en" {
		return fmt.Sprintf("Low average confidence (%.0f%%)", avg*100)
	}
	return fmt.Sprintf("평균 신뢰도 낮음(%.0f%%)", avg*100)
}
