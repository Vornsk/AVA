package scanengine

import (
	"os"
	"testing"
)

func resetEngine() {
	mu.Lock()
	jobs = map[string]*job{}
	order = nil
	seq = 0
	mu.Unlock()
}

// ScanRun 영속화 왕복: persist 후 재기동(글로벌 리셋)→Load 하면 완료 이력이 복원되고
// seq 가 이어져 신규 run id 충돌이 없다.
func TestRunPersistence(t *testing.T) {
	resetEngine()
	defer func() { resetEngine(); _ = os.Remove(runsFile) }()

	mu.Lock()
	jobs["SR-5"] = &job{pid: "p-1", run: ScanRun{ID: "SR-5", ProjectID: "p-1", Status: "완료", Findings: 3}, cancel: func() {}}
	order = []string{"SR-5"}
	seq = 5
	mu.Unlock()
	persistRuns()

	resetEngine() // 재기동 시뮬레이션(메모리만 비움, 파일 유지)
	if len(Runs()) != 0 {
		t.Fatal("리셋 후 비어야 함")
	}
	Load()

	runs := Runs()
	if len(runs) != 1 || runs[0].ID != "SR-5" || runs[0].Findings != 3 || runs[0].Status != "완료" {
		t.Fatalf("복원 실패: %+v", runs)
	}
	if got := RunsByProject("p-1"); len(got) != 1 {
		t.Errorf("프로젝트별 조회 %d건, want 1", len(got))
	}
	mu.Lock()
	s := seq
	mu.Unlock()
	if s != 5 {
		t.Errorf("seq=%d, want 5 (신규는 SR-6)", s)
	}
}
