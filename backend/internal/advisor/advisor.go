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
		for _, d := range ds {
			if d.Verdict.Allow {
				allow++
			} else {
				block++
			}
			confSum += d.Verdict.Confidence
			samples = append(samples, d.ID)
			models[d.Verdict.Model] = true
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
				Reason:      fmt.Sprintf("LLM 판단 이관 후보 (일관성 %.0f%%, %d건)", consistency*100, hits),
			},
		}
		var warns []string
		if consistency < 1.0 {
			warns = append(warns, fmt.Sprintf("반대 판정 %d건 — 오탐 위험, 섀도검증 권장(FR-6.4)", hits-maj))
		}
		if len(models) > 1 {
			warns = append(warns, "모델 버전 혼재 — 안정성 재확인")
		}
		if c.AvgConfidence < 0.7 {
			warns = append(warns, fmt.Sprintf("평균 신뢰도 낮음(%.0f%%)", c.AvgConfidence*100))
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

// Candidates — 현재 판단 로그로 기본 임계(빈도≥2, 일관성≥70%) 후보 도출.
func Candidates() []Candidate {
	return Analyze(llm.Decisions(), 2, 0.7)
}
