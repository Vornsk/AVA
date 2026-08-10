package rules

import (
	"os"
	"testing"
)

func TestDefaultRules(t *testing.T) {
	Load(Defaults())
	cases := []struct {
		method, path, want string
	}{
		{"GET", "/logout", "block"},
		{"GET", "/user/delete", "block"},
		{"DELETE", "/anything", "block"},
		{"GET", "/admin/users", "block"},
		{"GET", "/pay/confirm", "block"},
		{"POST", "/post", "llm"},
		{"GET", "/get", ""},
	}
	for _, c := range cases {
		if d := Evaluate(c.method, c.path); d.Action != c.want {
			t.Errorf("Evaluate(%s %s).Action = %q, want %q", c.method, c.path, d.Action, c.want)
		}
	}
}

func TestCustomRuleset(t *testing.T) {
	Load([]Rule{{Name: "x", Action: "block", PathPattern: "/danger"}})
	if d := Evaluate("GET", "/danger/1"); d.Action != "block" || d.Rule != "x" {
		t.Errorf("custom block failed: %+v", d)
	}
	if d := Evaluate("GET", "/safe"); d.Action != "" {
		t.Errorf("no match should pass, got %q", d.Action)
	}
	// 기본으로 복원 (다른 테스트/런타임 영향 방지)
	Load(Defaults())
}

// TestAdoptAndReload — HITL 채택이 (1) 즉시 활성 룰셋에 반영되고 (2) 앞쪽 우선순위이며
// (3) 파일로 영속화돼 재시작(LoadAdopted) 시 복원되는지 검증한다.
func TestAdoptAndReload(t *testing.T) {
	os.Remove(adoptedFile)
	t.Cleanup(func() { os.Remove(adoptedFile); adopted = nil; Load(Defaults()) })

	Load(Defaults())
	adopted = nil

	r := Rule{Name: "adopt-test", Action: "block", PathPattern: "/promoted", Reason: "test"}
	if !Add(r) {
		t.Fatal("Add 실패")
	}
	// (1) 즉시 반영
	if d := Evaluate("GET", "/promoted/x"); d.Action != "block" || d.Rule != "adopt-test" {
		t.Fatalf("채택 룰 미반영: %+v", d)
	}
	// (2) 중복 채택 거부
	if Add(r) {
		t.Error("동일 이름 중복 채택이 허용됨")
	}
	// (3) 영속화 → 재적재 복원
	adopted = nil
	Load(Defaults()) // 채택 룰이 룰셋에서 사라짐
	if d := Evaluate("GET", "/promoted/x"); d.Action == "block" {
		t.Fatal("Load 후에도 채택 룰이 남아있음(격리 실패)")
	}
	LoadAdopted() // 파일에서 복원
	if d := Evaluate("GET", "/promoted/x"); d.Action != "block" || d.Rule != "adopt-test" {
		t.Fatalf("LoadAdopted 복원 실패: %+v", d)
	}
	if got := Adopted(); len(got) != 1 || got[0].Name != "adopt-test" {
		t.Errorf("Adopted() = %+v", got)
	}
}
