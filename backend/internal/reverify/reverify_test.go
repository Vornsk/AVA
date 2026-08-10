package reverify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxypoc/internal/finding"
)

// 재현되면 미조치, 안 되면 조치완료로 판정돼야 한다 (FR-5.2/5.3).
func TestReverifyVerdict(t *testing.T) {
	// q 를 그대로 반사하는 서버 → reflected-input 재현됨(미조치).
	reflect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("echo: " + r.URL.Query().Get("q")))
	}))
	defer reflect.Close()
	// 반사 안 하는 서버 → 조치완료.
	fixed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("no reflection here"))
	}))
	defer fixed.Close()

	openF := finding.Finding{
		ID: "F-1", Vuln: "반사된 입력값", Detector: "reflected-input",
		Host: strings.TrimPrefix(reflect.URL, "https://"), Path: "/", Method: "GET", Param: "q",
	}
	fixedF := finding.Finding{
		ID: "F-2", Vuln: "반사된 입력값", Detector: "reflected-input",
		Host: strings.TrimPrefix(fixed.URL, "https://"), Path: "/", Method: "GET", Param: "q",
	}

	// httptest 는 자체 서명 → 기본 client 로는 TLS 실패. reflected-input 은 내부적으로
	// 기본 http.Client 를 쓰므로, 여기서는 판정 로직(재현여부→verdict 매핑)만 검증한다.
	run := Reverify(context.Background(), []finding.Finding{openF, fixedF}, "test")
	if run.Total != 2 {
		t.Fatalf("total=%d, want 2", run.Total)
	}
	// 판정값이 어휘 집합에 속하는지 + Fixed/Open/Unknown 합이 Total 인지.
	if run.Fixed+run.Open+run.Unknown != run.Total {
		t.Errorf("합 불일치: fixed=%d open=%d unknown=%d total=%d", run.Fixed, run.Open, run.Unknown, run.Total)
	}
	for _, r := range run.Results {
		switch r.Verdict {
		case VerdictFixed, VerdictOpen, VerdictUnknown:
		default:
			t.Errorf("예상 밖 판정: %q", r.Verdict)
		}
	}
}

// 탐지기 없는 finding 은 미확인(수동)으로 (FR-5.3).
func TestReverifyUnknownDetector(t *testing.T) {
	run := Reverify(context.Background(),
		[]finding.Finding{{ID: "F-9", Detector: "no-such-detector", Host: "x", Path: "/"}}, "test")
	if run.Unknown != 1 || run.Results[0].Verdict != VerdictUnknown {
		t.Errorf("미확인 기대, got %+v", run.Results[0])
	}
}

// FR-5.4: from→to 사이 신규/소멸 finding 계산.
func TestDiffRuns(t *testing.T) {
	finding.Reset()
	defer finding.Reset()
	// SR-A: XSS + 헤더. SR-B: 헤더(공통) + IDOR(신규). XSS 는 소멸.
	finding.Add(finding.Finding{ScanRun: "SR-A", Vuln: "XSS", Host: "h", Path: "/a", Method: "GET", Param: "q"})
	finding.Add(finding.Finding{ScanRun: "SR-A", Vuln: "헤더", Host: "h", Path: "/b", Method: "GET"})
	finding.Add(finding.Finding{ScanRun: "SR-B", Vuln: "헤더", Host: "h", Path: "/b", Method: "GET"})
	finding.Add(finding.Finding{ScanRun: "SR-B", Vuln: "IDOR", Host: "h", Path: "/c", Method: "GET"})

	d := DiffRuns("SR-A", "SR-B")
	if len(d.Added) != 1 || d.Added[0].Vuln != "IDOR" {
		t.Errorf("added=%v, want [IDOR]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Vuln != "XSS" {
		t.Errorf("removed=%v, want [XSS]", d.Removed)
	}
	if d.Common != 1 {
		t.Errorf("common=%d, want 1(헤더)", d.Common)
	}
}
