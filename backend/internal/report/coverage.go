package report

import (
	"fmt"
	"io"

	"github.com/xuri/excelize/v2"

	"proxypoc/internal/coverage"
)

// 점검결과표 (FR-4.3) — 도출리스트(취약점만)와 별개로 선택항목 전체의 수행 결과를 낸다.
// 문서 결과 어휘: 양호 | 취약 | 미점검 (해당없음은 진단자가 수동 지정). 자동 미지원은 미점검으로 보되 비고에 사유.

// CoverageRow — 점검결과표 한 행.
type CoverageRow struct {
	Scheme   string `json:"scheme"`
	Item     string `json:"item"`    // 점검항목 id
	Vuln     string `json:"vuln"`    // 취약점명
	Control  string `json:"control"` // 통제구분
	Risk     string `json:"risk"`    // 위험도
	Detector string `json:"detector"`
	Result   string `json:"result"` // 양호 | 취약 | 미점검
	Findings int    `json:"findings"`
	Remark   string `json:"remark"`
}

var coverageHeaders = []string{"점검항목", "취약점", "통제구분", "위험도", "탐지기", "점검결과", "발견 건수", "비고"}

// canonResult — 세부 상태를 문서의 결과 어휘(양호|취약|미점검)로 정규화.
func canonResult(status string) string {
	switch status {
	case "취약", "양호", "미점검":
		return status
	default: // 미지원(도구없음) | 미지원(수동)
		return "미점검"
	}
}

// CoverageRows — 현재 커버리지를 점검결과표 행으로 (스킴 순서 유지).
func CoverageRows() []CoverageRow {
	rep := coverage.Report()
	var rows []CoverageRow
	for _, sc := range rep.Schemes {
		for _, it := range sc.Items {
			risk := "-"
			if it.CheckItem.Risk != nil {
				risk = fmt.Sprintf("%d", *it.CheckItem.Risk)
			}
			det := "-"
			if len(it.Detectors) > 0 {
				det = join(it.Detectors)
			}
			rows = append(rows, CoverageRow{
				Scheme:   string(sc.Scheme),
				Item:     it.CheckItem.ID,
				Vuln:     it.VulnName,
				Control:  it.CheckItem.Control,
				Risk:     risk,
				Detector: det,
				Result:   canonResult(it.Status),
				Findings: it.Findings,
				Remark:   coverageRemark(it.Status),
			})
		}
	}
	return rows
}

func coverageRemark(status string) string {
	switch status {
	case "미지원(도구없음)":
		return "외부도구 미설치 → 수동/설치 후 재점검"
	case "미지원(수동)":
		return "자동 탐지기 없음 → 수동 점검"
	case "미점검":
		return "미실행"
	default:
		return ""
	}
}

// buildCoverage — 점검결과표 엑셀 구성. 스킴별 시트 + 요약 시트(FR-4.3).
func buildCoverage() (*excelize.File, int, error) {
	rep := coverage.Report()
	f := excelize.NewFile()

	const summary = "요약"
	f.SetSheetName("Sheet1", summary)
	headStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E9ECF5"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})

	// 요약 시트 헤더
	sumHead := []string{"스킴", "전체", "양호", "취약", "미점검", "자동가능", "수동"}
	writeHeader(f, summary, sumHead, headStyle)

	total := 0
	for si, sc := range rep.Schemes {
		// 상태 집계
		var good, vuln, notrun int
		for _, it := range sc.Items {
			switch canonResult(it.Status) {
			case "양호":
				good++
			case "취약":
				vuln++
			default:
				notrun++
			}
		}
		// 요약 행
		sumVals := []any{string(sc.Scheme), sc.Total, good, vuln, notrun, sc.Automatable, sc.Manual}
		for c, v := range sumVals {
			cell, _ := excelize.CoordinatesToCellName(c+1, si+2)
			_ = f.SetCellValue(summary, cell, v)
		}

		// 스킴별 시트
		sheet := sheetName(string(sc.Scheme))
		if _, err := f.NewSheet(sheet); err != nil {
			return nil, 0, err
		}
		writeHeader(f, sheet, coverageHeaders, headStyle)
		for r, it := range sc.Items {
			risk := "-"
			if it.CheckItem.Risk != nil {
				risk = fmt.Sprintf("%d", *it.CheckItem.Risk)
			}
			det := "-"
			if len(it.Detectors) > 0 {
				det = join(it.Detectors)
			}
			vals := []any{it.CheckItem.ID, it.VulnName, it.CheckItem.Control, risk, det,
				canonResult(it.Status), it.Findings, coverageRemark(it.Status)}
			for c, v := range vals {
				cell, _ := excelize.CoordinatesToCellName(c+1, r+2)
				_ = f.SetCellValue(sheet, cell, v)
			}
		}
		widths := []float64{14, 22, 14, 8, 20, 12, 10, 30}
		setWidths(f, sheet, widths)
		total += len(sc.Items)
	}
	setWidths(f, summary, []float64{18, 8, 8, 8, 8, 10, 8})
	f.SetActiveSheet(0)
	return f, total, nil
}

// WriteCoverageExcel — 점검결과표 xlsx 저장.
func WriteCoverageExcel(path string) (int, error) {
	f, n, err := buildCoverage()
	if err != nil {
		return 0, err
	}
	return n, f.SaveAs(path)
}

// WriteCoverageExcelTo — 점검결과표 xlsx 스트리밍 (웹 다운로드).
func WriteCoverageExcelTo(w io.Writer) (int, error) {
	f, n, err := buildCoverage()
	if err != nil {
		return 0, err
	}
	return n, f.Write(w)
}

// CoverageFilename — 기본 파일명.
func CoverageFilename() string { return "점검결과표.xlsx" }

// ── 공통 헬퍼 ──────────────────────────────────────────────
func writeHeader(f *excelize.File, sheet string, headers []string, style int) {
	for c, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(c+1, 1)
		_ = f.SetCellValue(sheet, cell, h)
		_ = f.SetCellStyle(sheet, cell, cell, style)
	}
	_ = f.SetPanes(sheet, &excelize.Panes{Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft"})
}

func setWidths(f *excelize.File, sheet string, widths []float64) {
	for c, w := range widths {
		col, _ := excelize.ColumnNumberToName(c + 1)
		_ = f.SetColWidth(sheet, col, col, w)
	}
}

// sheetName — 엑셀 시트명 제약(31자, 특수문자 금지) 대응.
func sheetName(s string) string {
	repl := []rune{}
	for _, r := range s {
		switch r {
		case ':', '\\', '/', '?', '*', '[', ']':
			repl = append(repl, '_')
		default:
			repl = append(repl, r)
		}
	}
	out := string(repl)
	if len([]rune(out)) > 31 {
		out = string([]rune(out)[:31])
	}
	return out
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
