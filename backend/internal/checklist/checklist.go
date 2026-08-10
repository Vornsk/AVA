// Package checklist — 점검항목 모듈 (문서 §6, 항목표 3계층 인코딩).
//
// 동일 취약점이 여러 스킴에 중복되므로 항목을 3층으로 분리해 탐지 로직을 재사용한다:
//
//	1층 Detector  — 탐지 "방법" (재사용 단위). 코드로 존재: internal/detector.
//	2층 VulnDef   — 취약점 "정의" (설명·분류, 중복 제거). detector id(들)를 참조.
//	3층 CheckItem — 스킴별 "점검항목" (규제 매핑·위험도). vuln id를 참조.
//
// 중복 취약점은 2·1층을 공유하고 3층만 스킴별로 둔다 → 탐지 로직 1개로 여러 탭 커버(§6.1).
// 항목표는 공유 설정(§4)이므로 checklist.config.yaml 로 분리해 버전관리 대상으로 둔다.
package checklist

import (
	"fmt"
	"log"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// Scheme — 점검 스킴(탭). 문서 §6.1.
type Scheme string

const (
	SchemeKII     Scheme = "주요정보통신기반시설"
	SchemeFinance Scheme = "전자금융"
	SchemeMobile  Scheme = "모바일"
)

// VulnDef — 2층: 취약점 정의(설명·분류, 중복 제거). detector id(들)로 1층에 연결.
type VulnDef struct {
	ID        string   `yaml:"id" json:"id"`
	Name      string   `yaml:"이름" json:"name"`
	Desc      string   `yaml:"설명" json:"desc"`
	Detectors []string `yaml:"detector" json:"detectors"` // 1층 detector id(들). 비면 자동탐지 미구현(수동)
	CWE       string   `yaml:"cwe,omitempty" json:"cwe,omitempty"`
}

// CheckItem — 3층: 스킴별 점검항목(규제 매핑·위험도). vuln id로 2층에 연결.
type CheckItem struct {
	ID      string `yaml:"id" json:"id"`
	Scheme  Scheme `yaml:"scheme" json:"scheme"`
	Control string `yaml:"통제구분,omitempty" json:"control,omitempty"` // 예: 서비스 보호
	Label   string `yaml:"평가항목,omitempty" json:"label,omitempty"`   // 스킴 공식 평가항목명(여러 항목이 같은 VulnDef를 참조할 때 구분)
	Vuln    string `yaml:"vuln" json:"vuln"`                        // 2층 VulnDef id
	Risk    *int   `yaml:"위험도,omitempty" json:"risk,omitempty"`     // 스킴 기준 위험도(전자금융 1~5). nil=미지정
}

// Set — 로드된 항목표(2·3층). 1층 Detector는 코드(internal/detector)에 있으므로 참조만.
type Set struct {
	Vulns      []VulnDef   `yaml:"vulns" json:"vulns"`
	CheckItems []CheckItem `yaml:"checkitems" json:"checkitems"`
}

// ── 패키지 전역 현재 항목표 ────────────────────────────────────────

var current = Default()

// 선택된 스킴/탭 (§3 Project "선택된 탭", §6). 비면 전체 스킴을 대상으로 본다.
var selected []Scheme

// Load — 항목표 교체.
func Load(s Set) { current = s }

// Current — 현재 항목표 스냅샷.
func Current() Set { return current }

// SetSelected — 진단 대상 스킴 선택. 빈 슬라이스면 전체(선택 해제).
func SetSelected(schemes []Scheme) { selected = schemes }

// Selected — 선택된 스킴. 미선택이면 항목표에 존재하는 전체 스킴을 반환한다.
func Selected() []Scheme {
	if len(selected) == 0 {
		return Schemes()
	}
	return append([]Scheme(nil), selected...)
}

// IsSelected — 해당 스킴이 진단 대상인지. 미선택 상태면 전체가 대상이다.
func IsSelected(s Scheme) bool {
	if len(selected) == 0 {
		return true
	}
	for _, x := range selected {
		if x == s {
			return true
		}
	}
	return false
}

// ── 조회 ───────────────────────────────────────────────────────────

// VulnByID — 2층 취약점 정의 조회.
func VulnByID(id string) (VulnDef, bool) {
	for _, v := range current.Vulns {
		if v.ID == id {
			return v, true
		}
	}
	return VulnDef{}, false
}

// CheckItemByID — 3층 점검항목 조회.
func CheckItemByID(id string) (CheckItem, bool) {
	for _, c := range current.CheckItems {
		if c.ID == id {
			return c, true
		}
	}
	return CheckItem{}, false
}

// CheckItemsByScheme — 특정 스킴(탭)의 점검항목들.
func CheckItemsByScheme(s Scheme) []CheckItem {
	var out []CheckItem
	for _, c := range current.CheckItems {
		if c.Scheme == s {
			out = append(out, c)
		}
	}
	return out
}

// Schemes — 항목표에 존재하는 스킴들(정렬).
func Schemes() []Scheme {
	seen := map[Scheme]bool{}
	for _, c := range current.CheckItems {
		seen[c.Scheme] = true
	}
	out := make([]Scheme, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// DetectorsFor — 점검항목이 (2층 경유) 사용하는 1층 detector id들. 매핑이 없으면 nil.
func DetectorsFor(checkItemID string) []string {
	c, ok := CheckItemByID(checkItemID)
	if !ok {
		return nil
	}
	v, ok := VulnByID(c.Vuln)
	if !ok {
		return nil
	}
	return v.Detectors
}

// CheckItemsForDetector — 역방향: 이 detector가 커버하는 점검항목들(스킴 무관).
func CheckItemsForDetector(detectorID string) []CheckItem {
	vuln := map[string]bool{}
	for _, v := range current.Vulns {
		for _, d := range v.Detectors {
			if d == detectorID {
				vuln[v.ID] = true
			}
		}
	}
	var out []CheckItem
	for _, c := range current.CheckItems {
		if vuln[c.Vuln] {
			out = append(out, c)
		}
	}
	return out
}

// ── 검증 ───────────────────────────────────────────────────────────

// Validate — 항목표 무결성 검사. available = 코드에 존재하는 detector id 집합.
// 반환: 사람이 읽는 이슈 목록(빈 슬라이스면 정상).
func Validate(available map[string]bool) []string {
	var issues []string
	vulnIDs := map[string]bool{}
	for _, v := range current.Vulns {
		if v.ID == "" {
			issues = append(issues, "빈 vuln id")
			continue
		}
		if vulnIDs[v.ID] {
			issues = append(issues, fmt.Sprintf("중복 vuln id: %s", v.ID))
		}
		vulnIDs[v.ID] = true
		for _, d := range v.Detectors {
			if !available[d] {
				issues = append(issues, fmt.Sprintf("vuln %s → 미존재 detector %q", v.ID, d))
			}
		}
	}
	seen := map[string]bool{}
	for _, c := range current.CheckItems {
		if c.ID == "" {
			issues = append(issues, "빈 checkitem id")
			continue
		}
		if seen[c.ID] {
			issues = append(issues, fmt.Sprintf("중복 checkitem id: %s", c.ID))
		}
		seen[c.ID] = true
		if !vulnIDs[c.Vuln] {
			issues = append(issues, fmt.Sprintf("checkitem %s → 미존재 vuln %q", c.ID, c.Vuln))
		}
	}
	return issues
}

// ── 파일 로드/생성 (공유 설정, §4) ─────────────────────────────────

// LoadOrCreate — 항목표 파일 로드. 없으면 기본 항목표로 생성하고 전역에 적용.
func LoadOrCreate(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		b, mErr := yaml.Marshal(Default())
		if mErr == nil {
			header := "# 점검항목표 — 공유/버전관리 (문서 §6, 3계층: VulnDef→CheckItem, detector는 코드)\n"
			_ = os.WriteFile(path, append([]byte(header), b...), 0644)
			log.Printf("점검항목표 생성: %s (기본값)", path)
		}
		return
	}
	var s Set
	if err := yaml.Unmarshal(data, &s); err != nil {
		log.Printf("점검항목표 파싱 실패(%s) — 기본값 사용: %v", path, err)
		return
	}
	Load(s)
	log.Printf("점검항목표 로드: %s (vuln %d, checkitem %d)", path, len(s.Vulns), len(s.CheckItems))
}

func risk(n int) *int { return &n }
