package project

import (
	"os"
	"testing"
)

func TestCreateActivateUpdate(t *testing.T) {
	Reset()
	defer func() { Reset(); _ = os.Remove(file) }()

	// 첫 프로젝트는 자동 활성.
	a := Create(Project{Name: "app-a", Scope: []string{"a.com"}, Schemes: []string{"전자금융"}})
	if a.ID != "p-1" {
		t.Fatalf("id=%s, want p-1", a.ID)
	}
	if act, ok := Active(); !ok || act.ID != "p-1" {
		t.Errorf("첫 프로젝트가 활성이어야 함, got %v/%v", act, ok)
	}
	if a.Created == "" || a.Modified == "" {
		t.Error("타임스탬프 누락")
	}

	// 둘째 생성 → 활성 유지(첫째).
	b := Create(Project{Name: "app-b", Scope: []string{"b.com"}})
	if act, _ := Active(); act.ID != "p-1" {
		t.Errorf("활성은 여전히 p-1이어야 함, got %s", act.ID)
	}
	if Count() != 2 {
		t.Errorf("count=%d, want 2", Count())
	}

	// 활성 전환.
	if !SetActive(b.ID) {
		t.Fatal("SetActive 실패")
	}
	if act, _ := Active(); act.ID != b.ID {
		t.Errorf("활성=%s, want %s", act.ID, b.ID)
	}
	if SetActive("p-999") {
		t.Error("없는 id 활성화는 실패해야 함")
	}

	// 수정.
	if !Update(a.ID, func(p *Project) { p.Scope = []string{"a.com", "a2.com"} }) {
		t.Fatal("Update 실패")
	}
	got, _ := Get(a.ID)
	if len(got.Scope) != 2 {
		t.Errorf("scope 미반영: %v", got.Scope)
	}
}

// 막다른 골목 개선 — 활성 프로젝트를 지우면 activeID 가 다른 살아있는 프로젝트로
// 재배정되고, 남은 게 없으면 ""(활성 없음)이 된다.
func TestDeleteActiveReassignsActive(t *testing.T) {
	Reset()
	defer func() { Reset(); _ = os.Remove(file) }()

	a := Create(Project{Name: "a"}) // 활성
	b := Create(Project{Name: "b"})
	if act, _ := Active(); act.ID != a.ID {
		t.Fatalf("초기 활성=%s, want %s", act.ID, a.ID)
	}

	// 활성(a) 삭제 → b 로 자동 전환
	if !Delete(a.ID) {
		t.Fatal("활성 프로젝트 삭제가 거부됨(허용해야 함)")
	}
	if act, ok := Active(); !ok || act.ID != b.ID {
		t.Fatalf("삭제 후 활성=%v/%v, want %s", act, ok, b.ID)
	}

	// 마지막 남은 활성(b) 삭제 → 활성 없음
	if !Delete(b.ID) {
		t.Fatal("마지막 프로젝트 삭제가 거부됨(허용해야 함)")
	}
	if act, ok := Active(); ok {
		t.Fatalf("마지막 삭제 후에도 활성 있음: %v (want 활성 없음)", act)
	}
	if n := len(List()); n != 0 { // List 는 살아있는 것만(Count 는 휴지통 포함)
		t.Errorf("살아있는 프로젝트=%d, want 0", n)
	}

	// 이미 휴지통인 것 재삭제 → false
	if Delete(a.ID) {
		t.Error("이미 휴지통인 프로젝트 재삭제가 성공하면 안 됨")
	}
}

func TestLoadRoundTrip(t *testing.T) {
	Reset()
	defer func() { Reset(); _ = os.Remove(file) }()
	Create(Project{Name: "persist-me", Scope: []string{"x.com"}})
	// 파일에서 다시 로드.
	Reset()
	Load()
	if Count() != 1 {
		t.Fatalf("로드 후 count=%d, want 1", Count())
	}
	if act, ok := Active(); !ok || act.Name != "persist-me" {
		t.Errorf("활성 복원 실패: %v/%v", act, ok)
	}
	// seq 복원 확인: 다음 생성은 p-2.
	if n := Create(Project{Name: "next"}); n.ID != "p-2" {
		t.Errorf("seq 복원 실패, id=%s want p-2", n.ID)
	}
}
