package checklist

// 커버리지 집계 (문서 §6 항목표 ↔ §5.3 진단결과 연결).
//
// "우리가 규제 항목표의 무엇을 자동으로 커버했고, 무엇이 미점검/수동으로 남았나"를
// 스킴(탭)별로 집계한다. 순수 함수로 두어 finding/scanengine 타입에 의존하지 않는다.
// 호출부(MCP 계층)가 detector 카탈로그·실행이력·finding 에서 map 을 만들어 넘긴다.

// 항목 상태값.
const (
	StatusVulnerable = "취약"        // 관련 finding 있음
	StatusClean      = "양호"        // 실행됐고 finding 없음 (문서 FR-4.3)
	StatusNotRun     = "미점검"       // 자동 가능하나 아직 실행 안 함
	StatusNoTool     = "미지원(도구없음)" // detector 매핑됐으나 외부도구 미설치
	StatusManual     = "미지원(수동)"   // detector 매핑 없음 → 수동 점검 대상
)

// ItemStatus — 점검항목 1개의 커버리지 상태.
type ItemStatus struct {
	CheckItem   CheckItem `json:"check_item"`
	VulnName    string    `json:"vuln_name"`
	Detectors   []string  `json:"detectors,omitempty"`
	Automatable bool      `json:"automatable"` // detector 매핑 존재
	Available   bool      `json:"available"`   // 매핑 detector 중 사용가능(설치됨) 하나 이상
	Ran         bool      `json:"ran"`         // 스캔에서 실행됨
	Findings    int       `json:"findings"`    // 이 항목 관련 finding 수
	Status      string    `json:"status"`
}

// SchemeCoverage — 스킴(탭) 단위 집계.
type SchemeCoverage struct {
	Scheme      Scheme       `json:"scheme"`
	Total       int          `json:"total"`
	Automatable int          `json:"automatable"` // 자동 가능 항목 수
	Ran         int          `json:"ran"`         // 실제 점검한 항목 수
	Vulnerable  int          `json:"vulnerable"`  // 취약 항목 수
	Manual      int          `json:"manual"`      // 수동 대상(미지원) 항목 수
	Items       []ItemStatus `json:"items"`
}

// Report — 전체 커버리지.
type Report struct {
	Schemes []SchemeCoverage `json:"schemes"`
}

// Coverage — 항목표 대비 진단 커버리지 집계.
//
//	available            : detector id → 사용가능(코드 존재 + 외부도구면 설치됨)
//	ran                  : detector id → 이번(누적) 스캔에서 실행됨
//	findingsByDetector   : detector id → 발생한 finding 수
func Coverage(available, ran map[string]bool, findingsByDetector map[string]int) Report {
	var rep Report
	for _, scheme := range Selected() { // 선택된 탭만 집계(미선택이면 전체)
		sc := SchemeCoverage{Scheme: scheme}
		for _, item := range CheckItemsByScheme(scheme) {
			st := statusFor(item, available, ran, findingsByDetector)
			sc.Items = append(sc.Items, st)
			sc.Total++
			if st.Automatable {
				sc.Automatable++
			} else {
				sc.Manual++
			}
			if st.Ran {
				sc.Ran++
			}
			if st.Findings > 0 {
				sc.Vulnerable++
			}
		}
		rep.Schemes = append(rep.Schemes, sc)
	}
	return rep
}

func statusFor(item CheckItem, available, ran map[string]bool, findingsByDetector map[string]int) ItemStatus {
	st := ItemStatus{CheckItem: item, Detectors: DetectorsFor(item.ID)}
	if v, ok := VulnByID(item.Vuln); ok {
		st.VulnName = v.Name
	}
	if item.Label != "" { // 스킴 공식 평가항목명 우선(전자금융처럼 여러 항목이 같은 VulnDef 참조 시)
		st.VulnName = item.Label
	}
	if len(st.Detectors) == 0 {
		st.Status = StatusManual
		return st
	}
	st.Automatable = true
	for _, d := range st.Detectors {
		if available[d] {
			st.Available = true
		}
		if ran[d] {
			st.Ran = true
		}
		st.Findings += findingsByDetector[d]
	}
	switch {
	case st.Findings > 0:
		st.Status = StatusVulnerable
	case st.Ran:
		st.Status = StatusClean
	case st.Available:
		st.Status = StatusNotRun
	default:
		st.Status = StatusNoTool
	}
	return st
}

// MapDetector — detector id 로 연결된 (vuln id들, checkitem id들). finding 태깅·역추적용.
func MapDetector(detectorID string) (vulnIDs, checkItemIDs []string) {
	for _, v := range current.Vulns {
		for _, d := range v.Detectors {
			if d == detectorID {
				vulnIDs = append(vulnIDs, v.ID)
			}
		}
	}
	for _, c := range CheckItemsForDetector(detectorID) {
		if IsSelected(c.Scheme) { // 선택된 탭의 항목으로만 태깅(§3 프로젝트 스킴)
			checkItemIDs = append(checkItemIDs, c.ID)
		}
	}
	return
}
