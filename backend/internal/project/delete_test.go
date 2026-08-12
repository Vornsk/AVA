package project

import "testing"

// 이슈 #14 — 소프트 삭제 모델 라이프사이클.
func TestSoftDeleteLifecycle(t *testing.T) {
	Reset()
	a := Create(Project{Name: "A"}) // 첫 생성 → 활성
	b := Create(Project{Name: "B"})

	if ap, ok := Active(); !ok || ap.ID != a.ID {
		t.Fatalf("활성 프로젝트가 %s 여야 함", a.ID)
	}

	// 활성 프로젝트는 삭제 불가
	if Delete(a.ID) {
		t.Fatal("활성 프로젝트 삭제가 허용됨(막아야 함)")
	}

	// 비활성 소프트 삭제
	if !Delete(b.ID) {
		t.Fatal("비활성 프로젝트 소프트 삭제 실패")
	}
	if Delete(b.ID) {
		t.Fatal("이미 휴지통인데 재삭제가 성공함")
	}

	// List 는 정상만, Trash 는 휴지통만
	if l := List(); len(l) != 1 || l[0].ID != a.ID {
		t.Fatalf("List에 삭제된 b가 남음: %+v", l)
	}
	if tr := Trash(); len(tr) != 1 || tr[0].ID != b.ID || tr[0].DeletedAt == "" {
		t.Fatalf("Trash 상태 이상: %+v", tr)
	}

	// 휴지통 프로젝트는 활성화 불가
	if SetActive(b.ID) {
		t.Fatal("휴지통 프로젝트 활성화가 허용됨")
	}

	// 복구
	if !Restore(b.ID) {
		t.Fatal("복구 실패")
	}
	if Restore(b.ID) {
		t.Fatal("휴지통이 아닌데 복구가 성공함")
	}
	if len(List()) != 2 || len(Trash()) != 0 {
		t.Fatalf("복구 후 상태 이상 list=%d trash=%d", len(List()), len(Trash()))
	}

	// 다시 삭제 후 영구삭제
	Delete(b.ID)
	if !Purge(b.ID) {
		t.Fatal("영구삭제 실패")
	}
	if _, ok := Get(b.ID); ok {
		t.Fatal("영구삭제 후에도 조회됨")
	}
	if Count() != 1 {
		t.Fatalf("Count=%d, want 1", Count())
	}
}
