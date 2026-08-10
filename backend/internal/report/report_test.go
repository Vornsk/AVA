package report

import (
	"bytes"
	"testing"

	"proxypoc/internal/finding"
)

func TestRows11Columns(t *testing.T) {
	finding.Reset()
	defer finding.Reset()
	// 같은 host+vuln 2건 → 취약점 건수 2. 다른 host 1건 → 건수 1.
	finding.Add(finding.Finding{Vuln: "XSS", Host: "a.com", Path: "/x", Method: "GET", Param: "q", Evidence: "<script>", Status: "신규", VulnDef: "vuln.xss"})
	finding.Add(finding.Finding{Vuln: "XSS", Host: "a.com", Path: "/y", Method: "GET", Param: "p", Status: "신규"})
	finding.Add(finding.Finding{Vuln: "헤더", Host: "b.com", Path: "/", Method: "GET", Status: "신규"})

	rows := Rows()
	if len(rows) != 3 {
		t.Fatalf("rows=%d, want 3", len(rows))
	}
	if len(Headers) != 11 {
		t.Fatalf("headers=%d, want 11", len(Headers))
	}
	// 첫 행 매핑 검증
	r := rows[0]
	if r.No != 1 || r.Target != "a.com" || r.MainURL != "https://a.com" ||
		r.Vuln != "XSS" || r.URL != "https://a.com/x" || r.Param != "q" || r.Payload != "<script>" {
		t.Errorf("row0 매핑 오류: %+v", r)
	}
	// 취약점 건수 집계: a.com XSS 2건.
	if r.Count != 2 {
		t.Errorf("a.com XSS 건수=%d, want 2", r.Count)
	}
	if rows[2].Count != 1 {
		t.Errorf("b.com 헤더 건수=%d, want 1", rows[2].Count)
	}
	// 비고에 검토상태 포함
	if r.Remark == "" {
		t.Error("비고 비어있음")
	}
}

func TestWriteExcelNonEmpty(t *testing.T) {
	finding.Reset()
	defer finding.Reset()
	finding.Add(finding.Finding{Vuln: "XSS", Host: "a.com", Path: "/x", Method: "GET", Status: "신규"})

	var buf bytes.Buffer
	n, err := WriteExcelTo(&buf)
	if err != nil {
		t.Fatalf("WriteExcelTo: %v", err)
	}
	if n != 1 {
		t.Errorf("n=%d, want 1", n)
	}
	// xlsx = zip → "PK" 매직으로 시작.
	if b := buf.Bytes(); len(b) < 4 || b[0] != 'P' || b[1] != 'K' {
		t.Errorf("유효한 xlsx(zip) 아님, len=%d", buf.Len())
	}
}
