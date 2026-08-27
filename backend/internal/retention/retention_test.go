package retention

import (
	"os"
	"testing"
	"time"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/finding"
	"proxypoc/internal/project"
)

// 이슈 #15 — 보존기간 초과분만 자동 영구삭제(+cascade), 보존기간 내는 유지.
func TestSweepExpiresOnlyOld(t *testing.T) {
	project.Reset()
	finding.Clear()
	now := time.Now().UTC()

	active := project.Create(project.Project{Name: "active"}) // 첫 생성 → 활성(삭제 대상 아님)
	old := project.Create(project.Project{Name: "old"})
	recent := project.Create(project.Project{Name: "recent"})
	finding.Add(finding.Finding{ProjectID: old.ID, Vuln: "x"}) // cascade 검증용

	// 소프트 삭제 후 DeletedAt 을 과거로 세팅(31일 전 / 5일 전)
	project.Delete(old.ID)
	project.Update(old.ID, func(p *project.Project) { p.DeletedAt = now.Add(-31 * 24 * time.Hour).Format(time.RFC3339) })
	project.Delete(recent.ID)
	project.Update(recent.ID, func(p *project.Project) { p.DeletedAt = now.Add(-5 * 24 * time.Hour).Format(time.RFC3339) })

	purged := Sweep(30, now)

	if len(purged) != 1 || purged[0] != old.ID {
		t.Fatalf("purged=%v, want [%s]", purged, old.ID)
	}
	if _, ok := project.Get(old.ID); ok {
		t.Fatal("보존기간 초과 프로젝트가 영구삭제 안 됨")
	}
	if len(finding.ByProject(old.ID)) != 0 {
		t.Fatal("cascade 실패: finding 이 안 지워짐")
	}
	if _, ok := project.Get(recent.ID); !ok {
		t.Fatal("보존기간 내 프로젝트가 잘못 삭제됨")
	}
	if _, ok := project.Get(active.ID); !ok {
		t.Fatal("활성(삭제 안 한) 프로젝트가 사라짐")
	}
}

// 이슈 #65 — 프로젝트 영구삭제 시 그 프로젝트의 공격면 파일(endpoints.<pid>.json)도 cascade 삭제.
func TestPurgeCascadeRemovesEndpointsFile(t *testing.T) {
	project.Reset()
	finding.Clear()

	p := project.Create(project.Project{Name: "target"}) // 첫 생성 → 활성
	// 그 프로젝트로 스왑해 공격면 파일을 만든다
	endpoints.SwitchProject(p.ID)
	endpoints.Record("http", "t.com", "GET", "/x", nil, false, "")
	f := "endpoints." + p.ID + ".json"
	if _, err := os.Stat(f); err != nil {
		t.Fatalf("공격면 파일 미생성: %v", err)
	}
	t.Cleanup(func() { endpoints.SwitchProject(""); endpoints.Reset(); _ = os.Remove(f) })

	// 소프트 삭제(활성 자동 전환으로 activeID 는 비게 됨) 후 영구삭제
	project.Delete(p.ID)
	endpoints.SwitchProject("") // 삭제 대상에서 detach — dump 가 파일을 되살리지 않게
	PurgeCascade(p.ID)

	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("영구삭제 후에도 공격면 파일이 남음: %s", f)
	}
}
