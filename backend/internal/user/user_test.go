package user

import (
	"os"
	"testing"
)

func TestPermissions(t *testing.T) {
	// 리더는 프로젝트 생성 가능, 수행원은 불가 (FR-1.4).
	if !Can(RoleLeader, "project:create") {
		t.Error("리더는 project:create 가능해야 함")
	}
	if Can(RoleAnalyst, "project:create") {
		t.Error("수행원은 project:create 불가해야 함")
	}
	// 둘 다 스캔·활성화 가능.
	for _, r := range []Role{RoleLeader, RoleAnalyst} {
		if !Can(r, "scan:run") || !Can(r, "project:activate") {
			t.Errorf("%s 는 scan:run/activate 가능해야 함", r)
		}
	}
	// 룰 승격은 리더만.
	if Can(RoleAnalyst, "rule:promote") {
		t.Error("수행원은 rule:promote 불가해야 함")
	}
}

func TestSeedAndSwitch(t *testing.T) {
	Reset()
	defer func() { Reset(); _ = os.Remove(file) }()

	Seed() // 기본 리더+수행원
	if len(List()) != 2 {
		t.Fatalf("시드 후 %d명, want 2", len(List()))
	}
	cur, ok := Current()
	if !ok || cur.Role != RoleLeader {
		t.Errorf("기본 현재 사용자는 리더여야 함, got %+v", cur)
	}
	// 인증: 올바른 비밀번호는 성공, 틀리면 실패 (bcrypt).
	if _, ok := Authenticate("leader", "leader123"); !ok {
		t.Error("올바른 자격증명 인증 실패")
	}
	if _, ok := Authenticate("leader", "wrong"); ok {
		t.Error("틀린 비밀번호가 인증됨")
	}

	a := Create("수행원1", RoleAnalyst, "pw12345")
	if !SetCurrent(a.ID) {
		t.Fatal("SetCurrent 실패")
	}
	if cur, _ := Current(); cur.Role != RoleAnalyst {
		t.Errorf("전환 후 수행원이어야 함, got %s", cur.Role)
	}
	// 전환된 수행원은 생성 권한 없음.
	if c, _ := Current(); Can(c.Role, "project:create") {
		t.Error("수행원 전환 후 project:create 불가해야 함")
	}
}
