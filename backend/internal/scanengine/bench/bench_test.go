package bench

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"proxypoc/internal/checklist"
	"proxypoc/internal/detector"
	"proxypoc/internal/llm"
)

// ── 유닛: 채점 로직 (대상 없이 합성 데이터로 항상 실행) ──

func gtFixture() GroundTruth {
	return GroundTruth{
		App:      "fix",
		Base:     "http://x",
		SiteWide: []string{"vuln.sec-headers"},
		Targets: []GTTarget{
			{Path: "/search", Expect: []string{"vuln.xss"}},
			{Path: "/item/{id}", Expect: []string{"vuln.sqli"}},
			{Path: "/user-safe", NotExpect: []string{"vuln.sqli"}},
			{Path: "/profile", Expect: []string{"vuln.info-exposure"}, NotExpect: []string{"vuln.access-control"}},
		},
	}
}

// TestScoreClasses — ★ 이슈 #49 합의 ②: safe 케이스 발동만 FP, 나머지는 미분류.
func TestScoreClasses(t *testing.T) {
	found := []Found{
		{Path: "/search", VulnDef: "vuln.xss", Detector: "reflected-input"},         // TP
		{Path: "/item/42", VulnDef: "vuln.sqli", Detector: "sqli"},                  // TP (구체경로 → canonical 매칭)
		{Path: "/user-safe", VulnDef: "vuln.sqli", Detector: "sqli-blind"},          // FP (정상 케이스에서 발동)
		{Path: "/profile", VulnDef: "vuln.access-control", Detector: "idor"},        // FP (접근통제는 정상)
		{Path: "/search", VulnDef: "vuln.open-redirect", Detector: "open-redirect"}, // 미분류
		{Path: "/search", VulnDef: "vuln.sec-headers", Detector: "sec-headers"},     // 전역 — 채점 제외
	}
	m := Score(found, gtFixture(), false, nil)

	if m.GroundTruth != 3 {
		t.Errorf("GT=%d (want 3: xss·sqli·info-exposure)", m.GroundTruth)
	}
	if m.TP != 2 || m.FP != 2 || m.Unclassified != 1 || m.SiteWide != 1 {
		t.Errorf("분류 오류: TP=%d FP=%d 미분류=%d 전역=%d (want 2,2,1,1)", m.TP, m.FP, m.Unclassified, m.SiteWide)
	}
	// /profile 의 info-exposure 는 안 나왔으므로 FN 1건.
	if m.FN != 1 || len(m.MissedList) != 1 {
		t.Errorf("FN=%d %v (want 1: /profile vuln.info-exposure)", m.FN, m.MissedList)
	}
	// ★ 미분류가 분모에 들어가면 안 된다 — 그게 합의 ② 의 핵심.
	if !approx(m.Precision, 0.5) { // TP 2 / (TP 2 + FP 2)
		t.Errorf("P=%.3f (want 0.5) — 미분류가 분모에 섞였는지 확인", m.Precision)
	}
	if !approx(m.FPRate, 0.5) {
		t.Errorf("FP율=%.3f (want 0.5)", m.FPRate)
	}
	if !approx(m.Recall, 2.0/3) {
		t.Errorf("R=%.3f (want 0.667)", m.Recall)
	}
}

// TestScorePairDedup — ★ 합의 ③: 매칭 단위는 (경로, 취약점) 쌍. 파라미터가 여럿이어도 1건.
func TestScorePairDedup(t *testing.T) {
	found := []Found{
		{Path: "/search", VulnDef: "vuln.xss", Detector: "reflected-input"},
		{Path: "/search", VulnDef: "vuln.xss", Detector: "reflected-input"}, // 같은 쌍 — 1건으로 접힘
		{Path: "/search", VulnDef: "vuln.xss", Detector: "dom-xss"},         // detector 만 다름 — 쌍은 동일
	}
	m := Score(found, gtFixture(), false, nil)
	if m.TP != 1 {
		t.Errorf("TP=%d (want 1) — 쌍 단위로 접히지 않았다", m.TP)
	}
	if m.Findings != 3 {
		t.Errorf("Findings=%d (want 3) — 원본 발견 건수는 접기 전이어야 한다", m.Findings)
	}
	// detector 분해는 발견 단위라 두 detector 가 각각 잡힌다.
	byDet := map[string]DetectorStat{}
	for _, s := range m.ByDetector {
		byDet[s.Detector] = s
	}
	if byDet["reflected-input"].TP != 2 || byDet["dom-xss"].TP != 1 {
		t.Errorf("detector 분해 오류: %+v", m.ByDetector)
	}
}

// TestScoreLLMFilter — LLM 이 오탐으로 판정한 건을 빼면 FP 가 줄고 TP 는 유지돼야 한다.
func TestScoreLLMFilter(t *testing.T) {
	found := []Found{
		{Path: "/search", VulnDef: "vuln.xss", Detector: "reflected-input"},
		{Path: "/user-safe", VulnDef: "vuln.sqli", Detector: "sqli-blind", LLMFP: true}, // LLM 이 오탐이라 판정
	}
	before := Score(found, gtFixture(), false, nil)
	after := Score(found, gtFixture(), true, nil)

	if before.FP != 1 || after.FP != 0 {
		t.Errorf("LLM 필터 전후 FP=%d→%d (want 1→0)", before.FP, after.FP)
	}
	if before.TP != after.TP {
		t.Errorf("LLM 필터가 정탐을 지웠다: TP=%d→%d", before.TP, after.TP)
	}
}

// TestLLMEffect — ★ 트리아지 효과는 "오탐을 줄였나"와 "정탐을 지웠나"를 같이 봐야 한다.
// 정탐까지 지우면 오탐률은 좋아지고 도구는 나빠진다.
func TestLLMEffect(t *testing.T) {
	found := []Found{
		{Path: "/user-safe", VulnDef: "vuln.sqli", Detector: "sqli-blind", LLMFP: true},      // 실제 오탐 → 잘 걸러냄
		{Path: "/search", VulnDef: "vuln.xss", Detector: "reflected-input", LLMFP: true},     // 실제 정탐 → 지움(위험)
		{Path: "/zzz", VulnDef: "vuln.ssrf", Detector: "ssrf", LLMFP: true},                  // 미분류
		{Path: "/search", VulnDef: "vuln.sec-headers", Detector: "sec-headers", LLMFP: true}, // 전역
		{Path: "/item/1", VulnDef: "vuln.sqli", Detector: "sqli"},                            // 미표시
	}
	e := LLMEffectOf(found, gtFixture())
	if e.Flagged != 4 {
		t.Errorf("표시=%d (want 4)", e.Flagged)
	}
	if e.CorrectFP != 1 || e.HarmfulFP != 1 || e.OtherFP != 2 {
		t.Errorf("교차표 오류: 정확=%d 유해=%d 기타=%d (want 1,1,2)", e.CorrectFP, e.HarmfulFP, e.OtherFP)
	}
	if !strings.Contains(e.Summary(), "정탐 1건을 지움") {
		t.Errorf("정탐 손실이 요약에 드러나지 않는다: %s", e.Summary())
	}
}

// TestReviewLLMCarriesEvidence — ★ 증적이 LLM 까지 실제로 전달되는가.
//
// 판정은 응답 문맥으로 한다(llm.reviewPrompt). 증적을 빼고 부르면 근거가 사라져 전부
// uncertain 이 되고, "LLM 이 오탐을 줄이는가"가 측정되지 않은 채 0건으로 보인다.
// 초기 구현이 실제로 그랬다 — 그때는 프로바이더 탓인지 배관 탓인지 구분할 수 없었다.
// mock 은 인코딩·비실행 컨텍스트 반사를 오탐으로 판정하므로 배관 검증에 그대로 쓸 수 있다.
func TestReviewLLMCarriesEvidence(t *testing.T) {
	llm.SetProvider(llm.New("mock", "", "", ""))
	t.Cleanup(func() { llm.SetProvider(nil) })

	cases := []struct {
		name string
		f    Found
		want bool
	}{
		{"인코딩 반사 → 오탐", Found{Path: "/a", VulnDef: "vuln.xss", Detector: "reflected-input",
			Severity: "medium", Response: "<p>results: &lt;script&gt;alert(1)&lt;/script&gt;</p>"}, true},
		{"textarea 반사 → 오탐", Found{Path: "/b", VulnDef: "vuln.xss", Detector: "reflected-input",
			Severity: "medium", Response: "<textarea><script>x</script></textarea>"}, true},
		{"raw 반사 → 오탐 아님", Found{Path: "/c", VulnDef: "vuln.xss", Detector: "reflected-input",
			Severity: "medium", Response: "<h1>Hello <script>alert(1)</script></h1>"}, false},
		{"증적 없음 → 판정 불가", Found{Path: "/d", VulnDef: "vuln.xss", Detector: "reflected-input"}, false},
		// 이슈 #54 — Content-Type 이 전달되는가. #49 오탐 5건이 전부 이 모양(raw 반사 + text/plain)이었다.
		{"raw 반사인데 text/plain → 오탐", Found{Path: "/e", VulnDef: "vuln.xss", Detector: "reflected-input",
			Severity: "medium", ContentType: "text/plain",
			Response: "<h1>Hello <script>alert(1)</script></h1>"}, true},
		{"raw 반사 + text/html → 오탐 아님(정탐 삭제 금지)", Found{Path: "/f", VulnDef: "vuln.xss", Detector: "reflected-input",
			Severity: "medium", ContentType: "text/html",
			Response: "<h1>Hello <script>alert(1)</script></h1>"}, false},
	}
	for _, c := range cases {
		if got := ReviewLLM(context.Background(), []Found{c.f})[0].LLMFP; got != c.want {
			t.Errorf("%s: LLMFP=%v want %v — 증적이 전달되지 않았을 수 있다", c.name, got, c.want)
		}
	}
}

// TestSiteWideExcluded — 전역 취약점은 정답에도 오탐에도 들어가지 않는다.
func TestSiteWideExcluded(t *testing.T) {
	var found []Found
	for _, p := range []string{"/search", "/user-safe", "/profile", "/nowhere"} {
		found = append(found, Found{Path: p, VulnDef: "vuln.sec-headers", Detector: "sec-headers"})
	}
	m := Score(found, gtFixture(), false, nil)
	if m.TP != 0 || m.FP != 0 || m.Unclassified != 0 {
		t.Errorf("전역 취약점이 채점에 섞였다: TP=%d FP=%d 미분류=%d", m.TP, m.FP, m.Unclassified)
	}
	if m.SiteWide != 4 {
		t.Errorf("전역 카운트=%d (want 4)", m.SiteWide)
	}
	if len(m.ByDetector) != 0 {
		t.Errorf("전역 취약점이 detector 분해를 덮었다: %+v", m.ByDetector)
	}
}

// TestVulnDefFallback — VulnDef 매핑이 없는 detector 도 채점에서 사라지지 않는다.
func TestVulnDefFallback(t *testing.T) {
	m := Score([]Found{{Path: "/x", Detector: "unmapped"}}, gtFixture(), false, nil)
	if m.Unclassified != 1 {
		t.Fatalf("미분류=%d (want 1)", m.Unclassified)
	}
	if got := m.UnclassifiedList[0]; got != "/x detector:unmapped" {
		t.Errorf("폴백 키=%q (want %q)", got, "/x detector:unmapped")
	}
}

// TestLoadGroundTruthConflict — expect·not_expect 가 겹치면 로드에서 잡는다(채점 모순 방지).
func TestLoadGroundTruthConflict(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bad.yaml")
	body := "app: bad\nbase: http://x\ntargets:\n  - path: /a\n    expect: [vuln.sqli]\n    not_expect: [vuln.sqli]\n"
	if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGroundTruth(f); err == nil {
		t.Error("expect·not_expect 충돌을 로드에서 잡지 못했다")
	}
}

// TestGroundTruthFilesValid — 저장된 정답셋이 스키마·참조 무결성을 지키는가.
// 대상 기동 없이 항상 돈다 — 정답셋 오타를 CI 없이도 즉시 잡는 방어선.
func TestGroundTruthFilesValid(t *testing.T) {
	files, err := gtFiles()
	if err != nil || len(files) == 0 {
		t.Skipf("정답셋 없음 (%v)", err)
	}
	for _, f := range files {
		gt, err := LoadGroundTruth(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		seen := map[string]bool{}
		for _, tg := range gt.Targets {
			if seen[tg.Path] {
				t.Errorf("%s: 경로 %s 가 중복 정의됐다", f, tg.Path)
			}
			seen[tg.Path] = true
			for _, v := range append(append([]string{}, tg.Expect...), tg.NotExpect...) {
				if _, ok := checklist.VulnByID(v); !ok {
					t.Errorf("%s: %s 의 %q 는 존재하지 않는 VulnDef id", f, tg.Path, v)
				}
			}
		}
		for _, v := range gt.SiteWide {
			if _, ok := checklist.VulnByID(v); !ok {
				t.Errorf("%s: site_wide 의 %q 는 존재하지 않는 VulnDef id", f, v)
			}
		}
	}
}

func approx(a, b float64) bool { return a-b < 1e-9 && b-a < 1e-9 }

// ── 통합: 실제 detector 실행 대조 ──
//
//	재현: (vulnapp 을 쓰려면) cd backend && go run ./cmd/vulnapp  기동 후 →
//	  cd backend && go test ./internal/scanengine/bench -run ScanBench -v
//	vulnlab 은 인프로세스 기동이라 대상 준비 없이 항상 돈다.
//	특정 정답셋만: SCANBENCH_GT=../../../../docs/scan-groundtruth/vulnlab.yaml go test ...
func TestScanBench(t *testing.T) {
	files, err := gtFiles()
	if err != nil {
		t.Fatalf("정답셋 탐색 실패: %v", err)
	}
	if len(files) == 0 {
		t.Skip("정답셋 YAML 없음 (docs/scan-groundtruth/*.yaml)")
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
			base, cleanup, ok := StartTarget(gt)
			if !ok {
				t.Skipf("대상 %s 미응답 — skip (기동 후 재실행)", gt.Base)
			}
			defer cleanup()
			benchOne(t, gt, base)
		})
	}
}

// gtFiles — 채점할 정답셋 파일 목록.
//
//	SCANBENCH_GT=<file>    : 그 파일 하나만.
//	SCANBENCH_GT_DIR=<dir> : 해당 폴더의 *.yaml 전부 (기본 docs/scan-groundtruth).
func gtFiles() ([]string, error) {
	if f := os.Getenv("SCANBENCH_GT"); f != "" {
		return []string{f}, nil
	}
	dir := os.Getenv("SCANBENCH_GT_DIR")
	if dir == "" {
		dir = "../../../../docs/scan-groundtruth"
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

// benchOne — 한 대상을 채점한다. detector 는 한 번만 돌리고, LLM 판정은 그 결과에 얹어 비교한다.
func benchOne(t *testing.T, gt GroundTruth, base string) {
	targets, err := SeedTargets(gt, base)
	if err != nil {
		t.Fatalf("대상 시드 실패: %v", err)
	}
	// 파괴성 detector 는 제외한다(FR-3.2 안전모드와 같은 기준). 벤치가 대상을 망가뜨리면 안 된다.
	var dets []detector.Detector
	var skipped []string
	for _, d := range detector.All() {
		if d.Destructive() {
			skipped = append(skipped, d.ID())
			continue
		}
		dets = append(dets, d)
	}

	t.Logf("스캔 벤치마크 — app=%s base=%s (대상 %d개 · 정답 쌍 %d개 · detector %d종, 파괴성 제외 %v)",
		gt.App, base, len(targets), countExpect(gt), len(dets), skipped)

	ctx, cancel := context.WithTimeout(context.Background(), Timeout())
	defer cancel()

	start := time.Now()
	found, err := RunDetectors(ctx, targets, dets, injectorFor(gt))
	if err != nil {
		// 부분 결과로 채점하면 벤치가 거짓 수치를 낸다 — 실패로 끝낸다.
		t.Fatalf("스캔 중단: %v", err)
	}
	dur := time.Since(start)

	t.Logf("%s", TableHeader())
	reachable := ReachableVulns(dets)
	m := Score(found, gt, false, reachable)
	m.Profile, m.Duration = "seeded", dur
	t.Logf("%s", m.Table())
	t.Logf("%s", m.Summary(15))

	// LLM 오탐 트리아지 전후 비교 (FR-3.3). 프로바이더가 없으면 판정이 전부 uncertain 이라 무의미.
	if name := SetupLLM(); name != "" {
		t.Logf("LLM 프로바이더: %s (SCANBENCH_LLM)", name)
	}
	if !LLMAvailable() {
		t.Logf("LLM 프로파일 skip — 프로바이더 미설정 (SCANBENCH_LLM=mock|ollama|anthropic|openai)")
	} else {
		ls := time.Now()
		reviewed := ReviewLLM(ctx, found)
		lm := Score(reviewed, gt, true, reachable)
		lm.Profile, lm.Duration = "seeded+llm", dur+time.Since(ls)
		t.Logf("%s", lm.Table())
		t.Logf("%s", lm.Summary(15))
		eff := LLMEffectOf(reviewed, gt)
		t.Logf("LLM 트리아지 효과: FP %d → %d · TP %d → %d · P %.1f%% → %.1f%%",
			m.FP, lm.FP, m.TP, lm.TP, m.Precision*100, lm.Precision*100)
		t.Logf("  %s", eff.Summary())
	}
	t.Logf("↑ 이 수치를 baseline 으로 기록하세요 (docs/scan-groundtruth/README.md).")
}

func countExpect(gt GroundTruth) int {
	n := 0
	for _, t := range gt.Targets {
		n += len(t.Expect)
	}
	return n
}
