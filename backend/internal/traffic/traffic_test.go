package traffic

import "testing"

func clear() { def = New() }

func TestRecordAndRecent(t *testing.T) {
	clear()
	Record("GET", "/a")
	Record("POST", "/b")
	if Count() != 2 {
		t.Fatalf("Count = %d, want 2", Count())
	}
	r := Recent(1)
	if len(r) != 1 || r[0].URL != "/b" || r[0].Method != "POST" {
		t.Errorf("Recent(1) = %v, want last entry /b", r)
	}
	if all := Recent(0); len(all) != 2 {
		t.Errorf("Recent(0) len = %d, want 2 (all)", len(all))
	}
}

func TestRingCap(t *testing.T) {
	clear()
	for i := 0; i < maxEntries+50; i++ {
		Record("GET", "/x")
	}
	if Count() != maxEntries {
		t.Errorf("Count = %d, want capped at %d", Count(), maxEntries)
	}
}

// 격리: 두 Log 인스턴스는 서로의 트래픽을 침범하지 않는다 (§5.1 Phase 2).
func TestLogIsolation(t *testing.T) {
	a, b := New(), New()
	a.Record("GET", "/a1")
	a.Record("GET", "/a2")
	b.Record("POST", "/b1")
	if a.Count() != 2 || b.Count() != 1 {
		t.Fatalf("격리 실패: a=%d(want 2) b=%d(want 1)", a.Count(), b.Count())
	}
	if r := b.Recent(1); len(r) != 1 || r[0].URL != "/b1" {
		t.Errorf("b 로그에 a 트래픽 유입: %v", r)
	}
}
