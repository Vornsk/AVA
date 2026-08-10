// Package report — 도출리스트/리포트 산출 (§5.4, report-exporter 모듈).
// 내부 데이터 모델(§3)은 전체 필드를 유지하되, 엑셀 출력은 제공 양식의 11개 컬럼만 적용한다(FR-4.1).
// 저장은 FR-1.6(사용자 지정 확장자)을 따르되, xlsx/pdf 로의 export 는 온디맨드로 제공한다.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/xuri/excelize/v2"

	"proxypoc/internal/checklist"
	"proxypoc/internal/finding"
	"proxypoc/internal/project"
)

// 도출리스트 11컬럼 헤더 (FR-4.1, 제공 엑셀 양식 그대로).
var Headers = []string{
	"NO", "대상명", "메인 URL", "발견 취약점", "발견 경로", "발견된 URL",
	"파라미터", "설명", "취약점 건수", "사용 구문", "비고",
}

// Row — 도출리스트 한 행 (11컬럼). 내부 Finding(§3)에서 이 11개만 투영한다.
type Row struct {
	No      int    `json:"no"`
	Target  string `json:"target"`   // 대상명
	MainURL string `json:"main_url"` // 메인 URL
	Vuln    string `json:"vuln"`     // 발견 취약점
	Path    string `json:"path"`     // 발견 경로
	URL     string `json:"url"`      // 발견된 URL
	Param   string `json:"param"`    // 파라미터
	Desc    string `json:"desc"`     // 설명
	Count   int    `json:"count"`    // 취약점 건수
	Payload string `json:"payload"`  // 사용 구문
	Remark  string `json:"remark"`   // 비고

	Severity string `json:"severity"` // 화면 표시용(심각도). xlsx 11컬럼에는 미포함.
}

// Rows — 현재 finding 들을 도출리스트 11컬럼으로 투영한다.
// 취약점 건수 = 동일 (대상명, 발견 취약점) 그룹의 finding 수.
func Rows() []Row {
	pid := "" // 활성 프로젝트로 스코프 (§5.1)
	if p, ok := project.Active(); ok {
		pid = p.ID
	}
	return RowsFor(pid)
}

// RowsFor — 특정 프로젝트의 도출리스트 (§5.1 FR-1.1, REST 리소스용).
func RowsFor(pid string) []Row {
	items := finding.ByProject(pid)

	// (host, vuln) 별 건수 집계.
	count := map[string]int{}
	for _, f := range items {
		count[f.Host+"|"+f.Vuln]++
	}

	rows := make([]Row, 0, len(items))
	for i, f := range items {
		rows = append(rows, Row{
			No:       i + 1,
			Target:   f.Host,
			MainURL:  "https://" + f.Host,
			Vuln:     f.Vuln,
			Path:     f.Path,
			URL:      "https://" + f.Host + f.Path,
			Param:    f.Param,
			Desc:     describe(f),
			Count:    count[f.Host+"|"+f.Vuln],
			Payload:  payloadCol(f),
			Remark:   remark(f),
			Severity: f.Severity,
		})
	}
	return rows
}

// payloadCol — "사용 구문" 컬럼: 재현 요청(실제 주입 URL)을 우선, 없으면 근거 설명.
func payloadCol(f finding.Finding) string {
	if f.Request != "" {
		return f.Request
	}
	return f.Evidence
}

// EvidenceHeaders — 증적 시트 컬럼 (FR-4.2).
var EvidenceHeaders = []string{"NO", "취약점", "심각도", "발견 URL", "파라미터", "재현 요청", "응답코드", "증명 응답(마스킹)"}

// EvidenceRow — 증적 한 행: 발견을 증명하는 재현 요청·응답.
type EvidenceRow struct {
	No       int    `json:"no"`
	Vuln     string `json:"vuln"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Param    string `json:"param"`
	Request  string `json:"request"`
	RespCode int    `json:"resp_code"`
	Response string `json:"response"`
}

// EvidenceRows — 활성 프로젝트 finding 중 증적(요청/응답)이 있는 항목들.
func EvidenceRows() []EvidenceRow {
	pid := ""
	if p, ok := project.Active(); ok {
		pid = p.ID
	}
	var out []EvidenceRow
	for _, f := range finding.ByProject(pid) {
		if f.Request == "" && f.Response == "" {
			continue // 증적 없는 항목(수동 등)은 제외
		}
		out = append(out, EvidenceRow{
			No: len(out) + 1, Vuln: f.Vuln, Severity: f.Severity,
			URL: "https://" + f.Host + f.Path, Param: f.Param,
			Request: f.Request, RespCode: f.RespCode, Response: f.Response,
		})
	}
	return out
}

// describe — 설명. 2층 VulnDef 설명을 우선 사용하고(§6), 없으면 취약점명.
func describe(f finding.Finding) string {
	if f.VulnDef != "" {
		if v, ok := checklist.VulnByID(f.VulnDef); ok && v.Desc != "" {
			return v.Desc
		}
	}
	if f.Remediation != "" {
		return f.Remediation
	}
	return f.Vuln
}

// remark — 비고. 검토상태·이행점검·LLM 판정을 요약.
func remark(f finding.Finding) string {
	parts := []string{"검토:" + f.Status}
	if f.ReverifyStatus != "" {
		parts = append(parts, "이행:"+f.ReverifyStatus)
	}
	if f.LLMVerdict != "" {
		parts = append(parts, "LLM:"+f.LLMVerdict)
	}
	if len(f.CheckItems) > 0 {
		parts = append(parts, "항목:"+strings.Join(f.CheckItems, ","))
	}
	return strings.Join(parts, " / ")
}

// build — 도출리스트 엑셀 파일을 메모리에 구성한다.
func build() (*excelize.File, int, error) {
	rows := Rows()
	f := excelize.NewFile()
	const sheet = "도출리스트"
	idx, err := f.NewSheet(sheet)
	if err != nil {
		return nil, 0, err
	}
	f.SetActiveSheet(idx)
	_ = f.DeleteSheet("Sheet1")

	// 헤더 (굵게)
	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#E9ECF5"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})
	for c, h := range Headers {
		cell, _ := excelize.CoordinatesToCellName(c+1, 1)
		_ = f.SetCellValue(sheet, cell, h)
		_ = f.SetCellStyle(sheet, cell, cell, style)
	}
	// 데이터
	for r, row := range rows {
		vals := []any{row.No, row.Target, row.MainURL, row.Vuln, row.Path, row.URL, row.Param, row.Desc, row.Count, row.Payload, row.Remark}
		for c, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(c+1, r+2)
			_ = f.SetCellValue(sheet, cell, v)
		}
	}
	// 컬럼 폭 (가독성)
	widths := []float64{5, 16, 24, 20, 20, 30, 12, 40, 10, 24, 28}
	for c, w := range widths {
		col, _ := excelize.ColumnNumberToName(c + 1)
		_ = f.SetColWidth(sheet, col, col, w)
	}
	_ = f.SetPanes(sheet, &excelize.Panes{Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft"})

	// ── 증적 시트 (FR-4.2): 재현 요청·증명 응답으로 발견을 객관적으로 뒷받침 ──
	buildEvidenceSheet(f, style)
	return f, len(rows), nil
}

// buildEvidenceSheet — 증적 시트를 추가(양식 도출리스트와 별개).
func buildEvidenceSheet(f *excelize.File, headerStyle int) {
	const esheet = "증적"
	if _, err := f.NewSheet(esheet); err != nil {
		return
	}
	for c, h := range EvidenceHeaders {
		cell, _ := excelize.CoordinatesToCellName(c+1, 1)
		_ = f.SetCellValue(esheet, cell, h)
		_ = f.SetCellStyle(esheet, cell, cell, headerStyle)
	}
	for r, ev := range EvidenceRows() {
		vals := []any{ev.No, ev.Vuln, ev.Severity, ev.URL, ev.Param, ev.Request, ev.RespCode, ev.Response}
		for c, v := range vals {
			cell, _ := excelize.CoordinatesToCellName(c+1, r+2)
			_ = f.SetCellValue(esheet, cell, v)
		}
	}
	widths := []float64{5, 22, 8, 32, 12, 46, 8, 60}
	for c, w := range widths {
		col, _ := excelize.ColumnNumberToName(c + 1)
		_ = f.SetColWidth(esheet, col, col, w)
	}
	_ = f.SetPanes(esheet, &excelize.Panes{Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft"})
}

// WriteExcel — 도출리스트를 xlsx 파일로 저장. 행 수 반환 (FR-4.1 export).
func WriteExcel(path string) (int, error) {
	f, n, err := build()
	if err != nil {
		return 0, err
	}
	if err := f.SaveAs(path); err != nil {
		return 0, err
	}
	return n, nil
}

// WriteExcelTo — 도출리스트 xlsx 를 writer 로 스트리밍 (웹 다운로드용).
func WriteExcelTo(w io.Writer) (int, error) {
	f, n, err := build()
	if err != nil {
		return 0, err
	}
	if err := f.Write(w); err != nil {
		return 0, err
	}
	return n, nil
}

// Filename — 기본 산출 파일명.
func Filename() string { return "도출리스트.xlsx" }

// summaryByVuln — (참고) 취약점별 건수 요약 문자열.
func Summary() string {
	c := map[string]int{}
	for _, r := range Rows() {
		c[r.Vuln] += 1
	}
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s×%d ", k, c[k])
	}
	return strings.TrimSpace(b.String())
}
