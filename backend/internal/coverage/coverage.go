// Package coverage — 라이브 상태에서 §6 점검항목 커버리지를 조립한다.
// checklist(순수) 는 detector/scanengine/finding 을 import 할 수 없으므로(순환),
// 상위 계층인 여기서 세 소스를 모아 checklist.Coverage 에 넘긴다. MCP·GUI 공용.
package coverage

import (
	"proxypoc/internal/checklist"
	"proxypoc/internal/detector"
	"proxypoc/internal/finding"
	"proxypoc/internal/project"
	"proxypoc/internal/scanengine"
)

// Inputs — 커버리지 집계 입력 3종을 현재 상태에서 만든다.
//
//	available: detector 사용가능(코드존재 + 외부도구면 설치됨)
//	ran      : 지금까지 어느 ScanRun 에서든 실행된 detector
//	byDet    : detector 별 finding 수
func Inputs() (available, ran map[string]bool, byDet map[string]int) {
	pid := "" // 활성 프로젝트로 스코프 (§5.1)
	if p, ok := project.Active(); ok {
		pid = p.ID
	}
	return InputsFor(pid)
}

// InputsFor — 특정 프로젝트 스코프의 커버리지 입력 (§5.1 FR-1.1, REST 리소스용).
func InputsFor(pid string) (available, ran map[string]bool, byDet map[string]int) {
	available = map[string]bool{}
	for _, d := range detector.Catalog() {
		available[d.ID] = d.Available == nil || *d.Available // 외부도구가 아니면 항상 사용가능
	}
	ran = map[string]bool{}
	for _, sr := range scanengine.RunsByProject(pid) {
		for _, id := range sr.Detectors {
			ran[id] = true
		}
	}
	byDet = map[string]int{}
	for _, f := range finding.ByProject(pid) {
		byDet[f.Detector]++
	}
	return
}

// Report — 활성 프로젝트 기준 스킴별 커버리지(§6 ↔ §5.3).
func Report() checklist.Report {
	return checklist.Coverage(Inputs())
}

// ReportFor — 특정 프로젝트 기준 커버리지 (§5.1 FR-1.1).
func ReportFor(pid string) checklist.Report {
	return checklist.Coverage(InputsFor(pid))
}
