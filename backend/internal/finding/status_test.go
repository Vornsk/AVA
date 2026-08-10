package finding

import (
	"os"
	"testing"
)

func TestStatusTransitionAndOptimisticLock(t *testing.T) {
	Reset()
	defer func() { Reset(); _ = os.Remove("findings.json") }()

	f := Add(Finding{Vuln: "XSS", Host: "a", Path: "/x"})
	if f.Status != "신규" || f.Version != 1 {
		t.Fatalf("초기 상태=%s v=%d, want 신규/1", f.Status, f.Version)
	}

	// 정상 전이: 신규 → 검토중 (v1 기대).
	u1, err := SetStatus(f.ID, "검토중", 1, "수행원A")
	if err != nil {
		t.Fatalf("전이 실패: %v", err)
	}
	if u1.Status != "검토중" || u1.Version != 2 || u1.Reviewer != "수행원A" {
		t.Errorf("전이 후 = %+v", u1)
	}

	// 잘못된 전이: 검토중 → 보고 (직접 불가).
	if _, err := SetStatus(f.ID, "보고", 2, "x"); err != ErrBadTransition {
		t.Errorf("잘못된 전이가 허용됨: %v", err)
	}

	// 낙관적 락: 오래된 버전(v1)으로 수정 시도 → 충돌.
	if _, err := SetStatus(f.ID, "확정", 1, "수행원B"); err != ErrConflict {
		t.Errorf("stale 버전이 충돌 안 남: %v", err)
	}

	// 최신 버전(v2)으로는 성공.
	u2, err := SetStatus(f.ID, "확정", 2, "수행원B")
	if err != nil || u2.Status != "확정" || u2.Version != 3 {
		t.Errorf("최신 버전 전이 실패: %+v %v", u2, err)
	}
}

func TestNextStates(t *testing.T) {
	if got := NextStates("검토중"); len(got) != 3 {
		t.Errorf("검토중 다음상태=%v, want 3(확정/오탐/보류)", got)
	}
	if got := NextStates("보고"); len(got) != 0 {
		t.Errorf("보고는 종료여야 함, got %v", got)
	}
}
