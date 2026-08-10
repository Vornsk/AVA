package scanengine

import (
	"context"
	"net/http"
	"testing"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/detector"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/finding"
	"proxypoc/internal/llm"
)

// slowDetector — 각 대상마다 delay 만큼 걸리는(취소 존중) 테스트용 탐지기.
type slowDetector struct{ delay time.Duration }

func (slowDetector) ID() string        { return "slow" }
func (slowDetector) Name() string      { return "slow" }
func (slowDetector) Destructive() bool { return false }
func (s slowDetector) Detect(ctx context.Context, t endpoints.Target, _ *http.Client, _ *auth.Injector) []finding.Finding {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
	}
	return nil
}

// destructiveDet — 파괴성 표시 테스트용 탐지기.
type destructiveDet struct{}

func (destructiveDet) ID() string        { return "destructive" }
func (destructiveDet) Name() string      { return "destructive" }
func (destructiveDet) Destructive() bool { return true }
func (destructiveDet) Detect(context.Context, endpoints.Target, *http.Client, *auth.Injector) []finding.Finding {
	return nil
}

func TestSafeModeForcesNonDestructive(t *testing.T) {
	defer SetSafeMode(false)
	targets := []endpoints.Target{{Host: "a"}}
	dets := []detector.Detector{destructiveDet{}}

	// 안전모드 OFF + opt-in: 파괴성 실행됨.
	SetSafeMode(false)
	sr := Start(targets, dets, Options{AllowDestructive: true})
	if sr.SafeMode {
		t.Error("SafeMode flag should be false when off")
	}
	if len(sr.Detectors) != 1 || len(sr.Skipped) != 0 {
		t.Errorf("off+opt-in: detectors=%v skipped=%v (want destructive run)", sr.Detectors, sr.Skipped)
	}

	// 안전모드 ON: opt-in 이어도 파괴성 강제 제외.
	SetSafeMode(true)
	sr = Start(targets, dets, Options{AllowDestructive: true})
	if !sr.SafeMode {
		t.Error("SafeMode flag should be true when on")
	}
	if len(sr.Detectors) != 0 || len(sr.Skipped) != 1 {
		t.Errorf("on+opt-in: detectors=%v skipped=%v (want destructive skipped)", sr.Detectors, sr.Skipped)
	}
}

// findingDet — 지정한 detector id 로 finding 하나를 내는 테스트 탐지기.
type findingDet struct{ det string }

func (f findingDet) ID() string      { return f.det }
func (f findingDet) Name() string    { return f.det }
func (findingDet) Destructive() bool { return false }
func (f findingDet) Detect(context.Context, endpoints.Target, *http.Client, *auth.Injector) []finding.Finding {
	return []finding.Finding{{Vuln: "x", Detector: f.det}}
}

// evidenceDet — 지정한 응답 증적을 담은 finding 을 내는 테스트 탐지기(LLM 트리아지 검증용).
type evidenceDet struct{ resp string }

func (evidenceDet) ID() string        { return "reflected-input" }
func (evidenceDet) Name() string      { return "reflected-input" }
func (evidenceDet) Destructive() bool { return false }
func (e evidenceDet) Detect(context.Context, endpoints.Target, *http.Client, *auth.Injector) []finding.Finding {
	return []finding.Finding{{Vuln: "반사", Severity: "medium", Detector: "reflected-input", Status: "신규", Response: e.resp}}
}

func waitDone(id string) {
	for i := 0; i < 80; i++ {
		if s, _ := Status(id); s.Status == "완료" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// LLM 오탐 검토: 판정을 finding에 '주석'하되 상태는 바꾸지 않는다(HITL — 사람이 결정).
// 약한 모델이 진짜 취약을 오탐 처리해도 자동으로 숨기지 않는 게 핵심.
func TestLLMTriage(t *testing.T) {
	SetSafeMode(false)
	llm.SetProvider(llm.MockProvider{})
	defer llm.SetProvider(nil)

	// 응답이 HTML 인코딩(&lt;) → mock이 false_positive 판정 → 주석되지만 상태는 신규 유지.
	finding.Reset()
	sr := Start([]endpoints.Target{{Host: "a"}}, []detector.Detector{evidenceDet{resp: "<body>&lt;script&gt; 인코딩됨</body>"}}, Options{LLMReview: true})
	waitDone(sr.ID)
	fp := finding.ByScanRun(sr.ID)
	if len(fp) != 1 || fp[0].LLMVerdict != "false_positive" {
		t.Fatalf("인코딩 반사는 LLM false_positive 주석돼야: %+v", fp)
	}
	if fp[0].Status != "신규" {
		t.Errorf("상태는 신규 유지돼야(자동조치 금지), got %q", fp[0].Status)
	}
	if s, _ := Status(sr.ID); s.LLMFlagged != 1 {
		t.Errorf("LLMFlagged=%d, want 1", s.LLMFlagged)
	}

	// 응답에 SQL 에러 → mock이 real 판정 → 신규 유지.
	finding.Reset()
	sr2 := Start([]endpoints.Target{{Host: "a"}}, []detector.Detector{evidenceDet{resp: "You have an error in your SQL syntax"}}, Options{LLMReview: true})
	waitDone(sr2.ID)
	real := finding.ByScanRun(sr2.ID)
	if len(real) != 1 || real[0].LLMVerdict != "real" || real[0].Status != "신규" {
		t.Fatalf("SQL 에러 증적은 real 주석 + 신규 유지돼야: %+v", real)
	}
}

// finding 이 저장될 때 §6 점검항목표(VulnDef/CheckItem)로 태깅돼야 한다.
func TestFindingTaggedWithCheckItems(t *testing.T) {
	SetSafeMode(false)
	sr := Start([]endpoints.Target{{Host: "a"}},
		[]detector.Detector{findingDet{det: "reflected-input"}}, Options{})
	// 완료 대기.
	for i := 0; i < 40; i++ {
		if s, _ := Status(sr.ID); s.Status == "완료" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	var got *finding.Finding
	for _, f := range finding.ByScanRun(sr.ID) {
		f := f
		got = &f
	}
	if got == nil {
		t.Fatal("finding 이 저장되지 않음")
	}
	if got.VulnDef != "vuln.xss" {
		t.Errorf("VulnDef=%q, want vuln.xss", got.VulnDef)
	}
	if len(got.CheckItems) < 2 { // KII-02 + WEB-SER-004
		t.Errorf("CheckItems=%v, want ≥2 (KII-02, WEB-SER-004)", got.CheckItems)
	}
}

func TestScanCancel(t *testing.T) {
	targets := []endpoints.Target{{Host: "a"}, {Host: "b"}, {Host: "c"}, {Host: "d"}}
	sr := Start(targets, []detector.Detector{slowDetector{delay: 200 * time.Millisecond}}, Options{})
	if sr.Status != "진행" || sr.Total != 4 {
		t.Fatalf("initial: status=%q total=%d", sr.Status, sr.Total)
	}

	time.Sleep(50 * time.Millisecond)
	if !Cancel(sr.ID) {
		t.Fatal("Cancel should succeed")
	}
	time.Sleep(300 * time.Millisecond)

	s, _ := Status(sr.ID)
	if s.Status != "중단" {
		t.Errorf("status after cancel = %q, want 중단", s.Status)
	}
	if s.Done >= s.Total {
		t.Errorf("cancelled scan should not complete all units: done=%d total=%d", s.Done, s.Total)
	}
}

func TestScanPauseResume(t *testing.T) {
	targets := []endpoints.Target{{Host: "a"}, {Host: "b"}, {Host: "c"}}
	sr := Start(targets, []detector.Detector{slowDetector{delay: 100 * time.Millisecond}}, Options{})

	time.Sleep(50 * time.Millisecond)
	if !Pause(sr.ID) {
		t.Fatal("Pause should succeed")
	}
	s, _ := Status(sr.ID)
	if s.Status != "일시정지" {
		t.Errorf("status after pause = %q, want 일시정지", s.Status)
	}
	doneAtPause := s.Done

	time.Sleep(400 * time.Millisecond) // 일시정지 중엔 진행이 (거의) 멈춰야 함
	if s2, _ := Status(sr.ID); s2.Done > doneAtPause+1 {
		t.Errorf("progress advanced while paused: %d → %d", doneAtPause, s2.Done)
	}

	if !Resume(sr.ID) {
		t.Fatal("Resume should succeed")
	}
	time.Sleep(500 * time.Millisecond)
	if s3, _ := Status(sr.ID); s3.Status != "완료" {
		t.Errorf("status after resume+wait = %q, want 완료", s3.Status)
	}
}
