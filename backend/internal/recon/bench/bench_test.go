package bench

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"proxypoc/internal/crawler"
)

// ── 유닛: canonical 폴딩 (대상 없이 항상 실행, 제품 NormalizePath 비의존) ──
func TestCanon(t *testing.T) {
	cases := map[string]string{
		"/rest/products/42":                       "/rest/products/{}",
		"/rest/products/{id}":                     "/rest/products/{}",     // GT 플레이스홀더
		"/rest/basket/:id":                        "/rest/basket/{}",       // :id 스타일
		"/api/Feedbacks":                          "/api/Feedbacks",        // 정적 세그먼트 보존(대소문자 유지)
		"/u/550e8400-e29b-41d4-a716-446655440000": "/u/{}",                 // uuid
		"/logs/2026-08-14":                        "/logs/{}",              // date
		"/t/0123456789abcdef0123":                 "/t/{}",                 // hex ≥16
		"/x/cafe":                                 "/x/cafe",               // 짧은 hex 는 단어로 보존
		"/rest/products/search?q=apple":           "/rest/products/search", // 쿼리 제거
		"/":                                       "/",
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

// ── 통합: 실제 정찰 실행 대조. docs/recon-groundtruth/ 의 정답셋을 순회하며 대상별 채점. ──
//
//	재현: 대상 웹 애플리케이션 기동 후 →
//	  cd backend && go test ./internal/recon/bench -run ReconBench -v
//	각 대상은 서브테스트로 격리되며, 미기동 대상은 skip(실패 아님).
//	특정 정답셋만: BENCH_GT=../../../../docs/recon-groundtruth/dvwa.yaml go test ...
func TestReconBench(t *testing.T) {
	files, err := gtFiles()
	if err != nil {
		t.Fatalf("정답셋 탐색 실패: %v", err)
	}
	if len(files) == 0 {
		t.Skip("정답셋 YAML 없음 (docs/recon-groundtruth/*.yaml)")
	}
	for _, f := range files {
		gt, err := LoadGroundTruth(f)
		if err != nil {
			t.Errorf("%s 로드 실패: %v", f, err)
			continue
		}
		name := gt.App
		if name == "" {
			name = filepath.Base(f)
		}
		t.Run(name, func(t *testing.T) {
			if !Reachable(gt.Base) {
				t.Skipf("대상 %s 미응답 — skip (기동 후 재실행)", gt.Base)
			}
			benchOne(t, gt)
		})
	}
}

// gtFiles — 채점할 정답셋 파일 목록.
//
//	BENCH_GT=<file>    : 그 파일 하나만.
//	BENCH_GT_DIR=<dir> : 해당 폴더의 *.yaml 전부 (기본 docs/recon-groundtruth).
func gtFiles() ([]string, error) {
	if f := os.Getenv("BENCH_GT"); f != "" {
		return []string{f}, nil
	}
	dir := os.Getenv("BENCH_GT_DIR")
	if dir == "" {
		dir = "../../../../docs/recon-groundtruth"
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// benchOne — 한 대상에 대해 프로파일별 채점 표를 출력한다.
func benchOne(t *testing.T, gt GroundTruth) {
	// 인증 크롤 설정(#31). 대상 간 격리를 위해 끝나면 해제.
	cleanup := ApplyAuth(gt.Auth)
	defer cleanup()
	if gt.Auth != nil {
		if gt.Auth.Login != nil {
			t.Logf("인증: 로그인 시퀀스 %s → 성공=%v", gt.Auth.Login.URL, LoginNow())
		} else {
			t.Logf("인증: 정적 쿠키/헤더 주입 (cookies=%d headers=%d)", len(gt.Auth.Cookies), len(gt.Auth.Headers))
		}
	}

	// ingest 는 명세만으로 얼마나 찾는지를 재는 프로파일이다 (이슈 #25). 크롤을 돌리지 않는다.
	profiles := []string{"ingest", "static"}
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
	t.Logf("↑ 이 수치를 baseline 으로 기록하세요 (README/이슈 #22·#23).")
}
