package finding

import (
	"os"
	"testing"
)

// Load 라운드트립: Add→persist 후 Reset→Load 하면 복원되고 seq 가 이어져 id 충돌이 없다.
func TestPersistLoadRoundTrip(t *testing.T) {
	Reset()
	defer func() { Reset(); _ = os.Remove("findings.json") }()

	a := Add(Finding{Vuln: "SQLi", Host: "h", Path: "/a"}) // F-1
	b := Add(Finding{Vuln: "XSS", Host: "h", Path: "/b"})  // F-2
	if a.ID != "F-1" || b.ID != "F-2" {
		t.Fatalf("ids = %s, %s", a.ID, b.ID)
	}

	// 메모리만 비우고(파일 유지) 재기동 시뮬레이션.
	Reset()
	if len(Snapshot()) != 0 {
		t.Fatal("Reset 후 비어야 함")
	}
	Load()

	got := Snapshot()
	if len(got) != 2 {
		t.Fatalf("복원 %d건, want 2", len(got))
	}
	if _, ok := ByID("F-2"); !ok {
		t.Error("F-2 복원 안 됨")
	}

	// 복원 후 신규 finding 은 F-3 이어야(seq 복원 확인).
	c := Add(Finding{Vuln: "CSRF", Host: "h", Path: "/c"})
	if c.ID != "F-3" {
		t.Errorf("복원 후 신규 id = %s, want F-3 (seq 이어짐)", c.ID)
	}
}

// 파일 없으면 Load 는 조용히 빈 상태.
func TestLoadNoFile(t *testing.T) {
	Reset()
	_ = os.Remove("findings.json")
	Load()
	if len(Snapshot()) != 0 {
		t.Error("파일 없으면 빈 상태여야 함")
	}
}
