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
