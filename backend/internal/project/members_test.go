package project

import (
	"os"
	"testing"
)

func TestMemberACL(t *testing.T) {
	Reset()
	defer func() { Reset(); _ = os.Remove(file) }()

	p := Create(Project{Name: "acme", Owner: "u-1"})

	// 소유자는 항상 멤버.
	if !IsMember(p.ID, "u-1") {
		t.Error("소유자가 멤버로 인식 안 됨")
	}
	// 미가입자는 멤버 아님.
	if IsMember(p.ID, "u-2") {
		t.Error("u-2 는 아직 멤버 아니어야")
	}
	// 추가 → 멤버.
	if !AddMember(p.ID, "u-2") {
		t.Fatal("AddMember 실패")
	}
	if !IsMember(p.ID, "u-2") {
		t.Error("추가 후 멤버여야")
	}
	// 중복 추가는 무시(멤버 1명 유지).
	AddMember(p.ID, "u-2")
	if g, _ := Get(p.ID); len(g.Members) != 1 {
		t.Errorf("중복 추가 방지 실패: %v", g.Members)
	}
	// 제거 → 비멤버.
	RemoveMember(p.ID, "u-2")
	if IsMember(p.ID, "u-2") {
		t.Error("제거 후 비멤버여야")
	}
}
