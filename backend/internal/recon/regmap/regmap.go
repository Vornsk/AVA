// Package regmap — 정찰 → 규제 점검항목 자동 매핑 (이슈 #42).
//
// AVA 의 핵심 가치는 진단 결과를 규제 항목표(KII/전자금융)에 연결하는 것이다. 지금까지는
// 취약점이 발견된 "뒤"에야(detector→VulnDef→CheckItem) 매핑됐다. 정찰 분류(#41)가 붙인
// 의미 라벨을 쓰면, 스캔 "전"에 "이 엔드포인트에 어떤 규제 점검항목이 적용되는가"를 안다.
//
// ★ 취약점 기반 커버리지(checklist.Coverage 의 취약/양호/미점검)와 다른 축이다. 여기서 내는 것은
// "적용 대상(후보)" — 무엇을 점검해야 하는지의 지도다. 두 결과를 섞지 않는다(합의 ③).
//
// 접근통제 후보: auth-only(인증 델타 #38=E1) + admin 라벨(분류 #41=E4) 조합인 엔드포인트는
// 접근통제 점검항목의 강조 대상으로 표시한다("숨겨진 관리 표면").
package regmap

import (
	"sort"

	"proxypoc/internal/checklist"
	"proxypoc/internal/endpoints"
)

// maxEndpointsPerItem — 항목당 나열할 후보 엔드포인트 상한(Count 는 전체를 센다).
const maxEndpointsPerItem = 100

// ItemCandidates — 한 점검항목에 적용되는 정찰 후보.
type ItemCandidates struct {
	CheckItem     checklist.CheckItem `json:"check_item"`
	VulnName      string              `json:"vuln_name"`
	Labels        []string            `json:"labels"`                   // 이 항목을 유발한 의미 라벨
	Count         int                 `json:"count"`                    // 적용 엔드포인트 수
	Endpoints     []string            `json:"endpoints,omitempty"`      // host+path 후보(상한)
	AccessControl bool                `json:"access_control,omitempty"` // auth-only+admin 조합이 걸린 접근통제 항목
}

// SchemeReport — 스킴(탭)별 정찰 규제 매핑.
type SchemeReport struct {
	Scheme     checklist.Scheme `json:"scheme"`
	Applicable int              `json:"applicable"` // 적용 대상 점검항목 수(= 커버)
	Mappable   int              `json:"mappable"`   // 의미 라벨로 도달 가능한 점검항목 수(모수)
	Items      []ItemCandidates `json:"items"`
	Gaps       []ItemCandidates `json:"gaps,omitempty"` // 도달 가능하나 발견 0건 = 정찰 공백 (이슈 #43)
}

// Report — 정찰 규제 매핑 1회.
type Report struct {
	Endpoints    int            `json:"endpoints"`                 // 전체 대상 수
	Labeled      int            `json:"labeled"`                   // 의미 라벨이 붙은 수
	AccessCtl    int            `json:"access_control_candidates"` // auth-only+admin 엔드포인트 수(E1+E4)
	Schemes      []SchemeReport `json:"schemes"`
	UnmappedList []string       `json:"unmapped_sample,omitempty"` // 라벨은 있으나 규제 매핑이 없는 라벨 샘플
}

type acc struct {
	item   checklist.CheckItem
	labels map[string]bool
	eps    map[string]bool
	ac     bool
}

// Build — 라벨이 붙은 대상들로 정찰 규제 매핑을 만든다. 선택된 스킴만 집계한다.
func Build(targets []endpoints.Target) Report {
	rep := Report{}
	items := map[string]*acc{} // checkitem id → 누적
	unmapped := map[string]bool{}

	for _, t := range targets {
		rep.Endpoints++
		// E1+E4: 인증 뒤에만 보이는 관리 표면 = 접근통제 강조 후보(라벨 매핑·스킴선택과 무관한 원신호).
		isAC := t.AuthOnly && hasLabel(t.Labels, "admin")
		if isAC {
			rep.AccessCtl++
		}
		ep := t.Host + t.Path

		mapped := false // 선택된 스킴에서 적용 점검항목이 하나라도 나왔는가
		for _, label := range t.Labels {
			cis := checklist.CheckItemsForLabel(label)
			if len(cis) == 0 {
				if isSemanticLabel(label) {
					unmapped[label] = true
				}
				continue
			}
			for _, ci := range cis {
				if !checklist.IsSelected(ci.Scheme) {
					continue
				}
				mapped = true
				a := items[ci.ID]
				if a == nil {
					a = &acc{item: ci, labels: map[string]bool{}, eps: map[string]bool{}}
					items[ci.ID] = a
				}
				a.labels[label] = true
				a.eps[ep] = true
				if isAC && ci.Vuln == checklist.AccessControlVuln {
					a.ac = true
				}
			}
		}
		if mapped { // 구조적 라벨(other·static·api)만 있는 엔드포인트는 규제 후보가 아니다
			rep.Labeled++
		}
	}

	// 스킴별로 묶어 정렬.
	byScheme := map[checklist.Scheme][]ItemCandidates{}
	for _, a := range items {
		ic := ItemCandidates{
			CheckItem:     a.item,
			VulnName:      vulnName(a.item),
			Labels:        sortedKeys(a.labels),
			Count:         len(a.eps),
			Endpoints:     cappedKeys(a.eps, maxEndpointsPerItem),
			AccessControl: a.ac,
		}
		byScheme[a.item.Scheme] = append(byScheme[a.item.Scheme], ic)
	}
	// 공백(#43) — 의미 라벨로 도달 가능한 점검항목 중 후보가 0건인 것. 모수를 "라벨 매핑이 있는
	// 항목"으로 잡는다: 정찰로 애초에 닿을 수 없는 항목까지 세면 공백이 노이즈가 된다.
	gapsByScheme := map[checklist.Scheme][]ItemCandidates{}
	for id, a := range mappable() {
		if items[id] != nil {
			continue // 이미 커버됨
		}
		gapsByScheme[a.item.Scheme] = append(gapsByScheme[a.item.Scheme], ItemCandidates{
			CheckItem: a.item, VulnName: vulnName(a.item), Labels: sortedKeys(a.labels),
		})
	}

	for _, scheme := range checklist.Selected() {
		its, gaps := byScheme[scheme], gapsByScheme[scheme]
		if len(its) == 0 && len(gaps) == 0 {
			continue
		}
		sortItems(its)
		sortItems(gaps)
		rep.Schemes = append(rep.Schemes, SchemeReport{
			Scheme: scheme, Applicable: len(its), Mappable: len(its) + len(gaps), Items: its, Gaps: gaps,
		})
	}
	rep.UnmappedList = cappedKeys(unmapped, 10)
	return rep
}

// mappable — 의미 라벨로 도달 가능한 점검항목(선택 스킴만). id → 항목·유발 라벨.
// 커버/공백의 모수다. 라벨 매핑(checklist.labelVulns)과 현재 항목표에서만 나오므로,
// 커스텀 항목표 YAML 을 넣어도 그대로 따라간다.
func mappable() map[string]*acc {
	out := map[string]*acc{}
	for _, label := range checklist.SemanticLabels() {
		for _, ci := range checklist.CheckItemsForLabel(label) {
			if !checklist.IsSelected(ci.Scheme) {
				continue
			}
			a := out[ci.ID]
			if a == nil {
				a = &acc{item: ci, labels: map[string]bool{}, eps: map[string]bool{}}
				out[ci.ID] = a
			}
			a.labels[label] = true
		}
	}
	return out
}

// sortItems — 점검항목 id 순 정렬(커버·공백 공통).
func sortItems(its []ItemCandidates) {
	sort.Slice(its, func(i, j int) bool { return lessCheckItemID(its[i].CheckItem.ID, its[j].CheckItem.ID) })
}

func vulnName(ci checklist.CheckItem) string {
	if ci.Label != "" {
		return ci.Label
	}
	if v, ok := checklist.VulnByID(ci.Vuln); ok {
		return v.Name
	}
	return ci.Vuln
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// isSemanticLabel — 규제 매핑이 있어야 할 의미 라벨인가(구조적 api·static·other 제외).
// 목록을 여기 복제하지 않고 checklist 의 라벨 매핑을 그대로 묻는다(드리프트 방지, #43).
func isSemanticLabel(label string) bool {
	return len(checklist.VulnsForLabel(label)) > 0
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func cappedKeys(m map[string]bool, limit int) []string {
	out := sortedKeys(m)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// lessCheckItemID — 숫자 id(전자금융 1~66)는 수치로, 그 외(KII 알파벳)는 문자열로 정렬.
func lessCheckItemID(a, b string) bool {
	na, aok := atoi(a)
	nb, bok := atoi(b)
	if aok && bok {
		return na < nb
	}
	if aok != bok {
		return aok // 숫자를 앞에
	}
	return a < b
}

func atoi(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}
