package report

import (
	"bytes"
	"testing"

	"proxypoc/internal/finding"
)

func TestCoverageRowsResult(t *testing.T) {
	finding.Reset()
	defer finding.Reset()

	rows := CoverageRows()
	if len(rows) == 0 {
		t.Fatal("점검결과표 행이 비어있음 (기본 항목표가 있어야 함)")
	}
	// 모든 결과값은 문서 어휘로 정규화돼야 한다.
	for _, r := range rows {
		switch r.Result {
		case "양호", "취약", "미점검":
		default:
			t.Errorf("정규화 안 된 결과값: %q (item %s)", r.Result, r.Item)
		}
	}
	// 도출리스트와 달리 취약점 없어도 전 항목이 나온다(양호/미점검 포함).
	var hasNotRun bool
	for _, r := range rows {
		if r.Result == "미점검" {
			hasNotRun = true
		}
	}
	if !hasNotRun {
		t.Error("finding 없을 때 전 항목이 미점검이어야 함")
	}
}

func TestWriteCoverageExcel(t *testing.T) {
	finding.Reset()
	defer finding.Reset()
	var buf bytes.Buffer
	n, err := WriteCoverageExcelTo(&buf)
	if err != nil {
		t.Fatalf("WriteCoverageExcelTo: %v", err)
	}
	if n == 0 {
		t.Error("항목 수 0")
	}
	if b := buf.Bytes(); len(b) < 4 || b[0] != 'P' || b[1] != 'K' {
		t.Errorf("유효한 xlsx 아님, len=%d", buf.Len())
	}
}
