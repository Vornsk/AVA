package bench

import (
	"os"
	"testing"
	"time"

	"proxypoc/internal/crawler"
)

// ── 유닛: canonical 폴딩 (대상 없이 항상 실행, 제품 NormalizePath 비의존) ──
func TestCanon(t *testing.T) {
	cases := map[string]string{
		"/rest/products/42":                            "/rest/products/{}",
		"/rest/products/{id}":                          "/rest/products/{}", // GT 플레이스홀더
		"/rest/basket/:id":                             "/rest/basket/{}",   // :id 스타일
		"/api/Feedbacks":                               "/api/Feedbacks",    // 정적 세그먼트 보존(대소문자 유지)
		"/u/550e8400-e29b-41d4-a716-446655440000":      "/u/{}",             // uuid
		"/logs/2026-08-14":                             "/logs/{}",          // date
		"/t/0123456789abcdef0123":                      "/t/{}",             // hex ≥16
		"/x/cafe":                                      "/x/cafe",           // 짧은 hex 는 단어로 보존
		"/rest/products/search?q=apple":                "/rest/products/search", // 쿼리 제거
		"/":                                            "/",
	}
	for in, want := range cases {
		if got := Canon(in); got != want {
			t.Errorf("Canon(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── 유닛: 채점 지표 (대상 없이 합성 데이터로) ──
func TestScore(t *testing.T) {
	gt := GroundTruth{Endpoints: []GTEndpoint{
		{Method: "GET", Path: "/rest/products/{id}"},
		{Method: "POST", Path: "/api/Feedbacks"},
		{Method: "GET", Path: "/rest/user/whoami"},
	}}
	disc := []Endpoint{
		{Method: "GET", Path: "/rest/products/1"}, // ↓ 둘은 canonical 로 1개
		{Method: "GET", Path: "/rest/products/2"},
		{Method: "POST", Path: "/api/Feedbacks"},
		{Method: "GET", Path: "/admin/secret"}, // 오탐
	}
	m := Score(disc, len(disc), gt)

	if m.GroundTruth != 3 || m.Discovered != 3 || m.Matched != 2 || m.Extra != 1 || m.Missed != 1 {
		t.Fatalf("count 오류: %+v", m)
	}
	if !approx(m.Precision, 2.0/3) || !approx(m.Recall, 2.0/3) || !approx(m.F1, 2.0/3) {
		t.Errorf("P/R/F1 오류: P=%.3f R=%.3f F1=%.3f", m.Precision, m.Recall, m.F1)
	}
	if !approx(m.FPRate, 1.0/3) {
		t.Errorf("FPRate 오류: %.3f", m.FPRate)
	}
	if !approx(m.Inflation, 4.0/3) { // rawCount 4 / canonical 3
		t.Errorf("Inflation 오류: %.3f", m.Inflation)
	}
}

func approx(a, b float64) bool { return a-b < 1e-9 && b-a < 1e-9 }

// ── 통합: 실제 정찰 실행 대조. 대상 미기동이면 skip ──
//
//	재현: Juice Shop 기동 후 → cd backend && go test ./internal/recon/bench -run ReconBench -v
func TestReconBench(t *testing.T) {
	gtPath := os.Getenv("BENCH_GT")
	if gtPath == "" {
		gtPath = "../../../../docs/recon-groundtruth/juice-shop.yaml"
	}
	gt, err := LoadGroundTruth(gtPath)
	if err != nil {
		t.Fatalf("ground-truth 로드 실패: %v", err)
	}
	if !Reachable(gt.Base) {
		t.Skipf("대상 %s 미응답 — 벤치 skip. (예: Juice Shop 기동 후 재실행)", gt.Base)
	}

	profiles := []string{"static"}
	if crawler.HeadlessAvailable() {
		profiles = append(profiles, "headless")
	} else {
		t.Logf("headless 프로파일 skip — 이 환경에 Chrome/Chromium 없음")
	}

	t.Logf("정찰 벤치마크 — app=%s base=%s (GT %d개)", gt.App, gt.Base, len(gt.Endpoints))
	t.Logf("%s", TableHeader())
	for _, p := range profiles {
		disc, raw, pages, dur, err := RunProfile(gt.Base, p, 400, 120*time.Second)
		if err != nil {
			t.Errorf("[%s] 실행 실패: %v", p, err)
			continue
		}
		m := Score(disc, raw, gt)
		m.Profile, m.Pages, m.Duration = p, pages, dur
		t.Logf("%s", m.Table())
		t.Logf("%s", m.Summary(10))
	}
	t.Logf("↑ 이 수치를 이슈 #22 baseline 으로 기록하세요 (static/headless 각각).")
}
