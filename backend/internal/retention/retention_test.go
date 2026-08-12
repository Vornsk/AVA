package retention

import (
	"testing"
	"time"

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
