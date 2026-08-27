package endpoints

import (
	"os"
	"testing"
)

// 이슈 #65 — 공격면 트리를 프로젝트별 파일로 스왑.

func cleanupSwitch(t *testing.T, files ...string) {
	t.Helper()
	for _, f := range files {
		_ = os.Remove(f)
	}
	t.Cleanup(func() {
		SwitchProject("") // def 를 인메모리로 되돌려 다음 테스트 오염 방지
		Reset()
		for _, f := range files {
			_ = os.Remove(f)
		}
	})
}

// 프로젝트별로 파일이 분리되고, 전환하면 그 프로젝트의 공격면만 보인다.
func TestSwitchProjectIsolatesPerProject(t *testing.T) {
	fa, fb := projectFile("t-a"), projectFile("t-b")
	SwitchProject("") // 알려진 시작 상태
	Reset()
	cleanupSwitch(t, fa, fb, legacyEndpointsFile)

	// A 로 전환 후 기록 → A 파일 생성
	SwitchProject("t-a")
	Record("http", "a.com", "GET", "/a", nil, false, "")
	if _, err := os.Stat(fa); err != nil {
		t.Fatalf("A 파일 미생성: %v", err)
	}

	// B 로 전환 → A 의 엔드포인트가 안 보인다(격리)
	SwitchProject("t-b")
	if n := len(Targets()); n != 0 {
		t.Errorf("B 로 전환했는데 A 엔드포인트가 보임: %d개", n)
	}
	Record("http", "b.com", "GET", "/b", nil, false, "")

	// A 로 복귀 → A 것만 보인다(B 것 안 보임)
	SwitchProject("t-a")
	tg := Targets()
	if len(tg) != 1 || tg[0].Host != "a.com" {
		t.Fatalf("A 복귀 후 = %v, want [a.com]", tg)
	}

	// RemoveProjectFile → 파일 삭제
	SwitchProject("") // detach 해서 dump 가 다시 쓰지 않게
	RemoveProjectFile("t-a")
	if _, err := os.Stat(fa); !os.IsNotExist(err) {
		t.Error("RemoveProjectFile 후에도 A 파일이 남음")
	}
}

// 활성 없음(pid="")이면 인메모리 — 파일을 쓰지 않는다.
func TestSwitchProjectNoActiveInMemory(t *testing.T) {
	SwitchProject("")
	Reset()
	cleanupSwitch(t, projectFile("t-c"))

	SwitchProject("") // 활성 없음
	Record("http", "c.com", "GET", "/c", nil, false, "")
	// 인메모리엔 있지만 파일은 없다
	if n := len(Targets()); n != 1 {
		t.Errorf("인메모리 기록=%d, want 1", n)
	}
	if _, err := os.Stat(projectFile("t-c")); err == nil {
		t.Error("활성 없음인데 파일이 생성됨")
	}
	if _, err := os.Stat("endpoints..json"); err == nil {
		os.Remove("endpoints..json")
		t.Error("빈 pid 로 잘못된 파일명(endpoints..json)이 생성됨")
	}
}

// 이행 전 전역 endpoints.json 은 최초 프로젝트 활성화 때 그 프로젝트가 1회 흡수(rename)한다.
func TestSwitchProjectMigratesLegacy(t *testing.T) {
	fmig := projectFile("t-mig")
	SwitchProject("")
	Reset()
	cleanupSwitch(t, fmig, legacyEndpointsFile)

	// legacy 전역 파일을 명세대로 만들어 둔다
	legacy := &Tree{roots: map[string]*node{}, name: legacyEndpointsFile}
	legacy.Record("http", "legacy.com", "GET", "/x", nil, false, "")
	if _, err := os.Stat(legacyEndpointsFile); err != nil {
		t.Fatalf("legacy 파일 준비 실패: %v", err)
	}

	// 프로젝트 파일이 없는 프로젝트로 전환 → legacy 흡수
	SwitchProject("t-mig")
	tg := Targets()
	if len(tg) != 1 || tg[0].Host != "legacy.com" {
		t.Fatalf("legacy 흡수 실패: %v", tg)
	}
	if _, err := os.Stat(legacyEndpointsFile); !os.IsNotExist(err) {
		t.Error("흡수 후에도 legacy endpoints.json 이 남음")
	}
	if _, err := os.Stat(fmig); err != nil {
		t.Errorf("프로젝트 파일 미생성: %v", err)
	}

	// 두 번째 프로젝트는 흡수할 legacy 가 없으므로 빈 트리
	SwitchProject("t-mig2")
	if n := len(Targets()); n != 0 {
		t.Errorf("두 번째 프로젝트가 legacy 를 또 흡수함: %d개", n)
	}
	os.Remove(projectFile("t-mig2"))
}
