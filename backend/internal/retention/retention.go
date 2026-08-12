// Package retention — 휴지통 프로젝트의 보존기간(기본 30일) 경과 자동 영구삭제 (이슈 #15).
// 소프트 삭제(이슈 #14)된 프로젝트를 백그라운드 스위퍼가 주기적으로 정리한다.
// 서버가 꺼져 있던 기간은 다음 기동 시 정리된다(기동 시 1회 + 6시간 주기).
package retention

import (
	"fmt"
	"log"
	"time"

	"proxypoc/internal/audit"
	"proxypoc/internal/finding"
	"proxypoc/internal/project"
	"proxypoc/internal/scanengine"
)

// sweepInterval — 스위퍼 주기. 30일 보존이라 촘촘할 필요 없고 비용도 무시할 수준.
const sweepInterval = 6 * time.Hour

// PurgeCascade — 프로젝트 영구삭제 + 관련 findings·scanruns cascade 제거 (이슈 #14/#15 공용).
// 반환: 지운 findings·scanruns 수.
func PurgeCascade(pid string) (findingsDeleted, scanrunsDeleted int) {
	findingsDeleted = finding.DeleteByProject(pid)
	scanrunsDeleted = scanengine.DeleteByProject(pid)
	project.Purge(pid)
	return
}

// Sweep — 보존기간(retentionDays) 초과한 휴지통 프로젝트를 영구삭제 (이슈 #15).
// now 를 주입받아 테스트 가능. 자동 삭제는 감사에 actor=system 으로 남긴다. 반환: 삭제한 프로젝트 id.
func Sweep(retentionDays int, now time.Time) []string {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	cutoff := now.Add(-time.Duration(retentionDays) * 24 * time.Hour)
	var purged []string
	for _, p := range project.Trash() {
		t, err := time.Parse(time.RFC3339, p.DeletedAt)
		if err != nil {
			continue // 시각 파싱 불가면 건너뜀(안전)
		}
		if t.After(cutoff) {
			continue // 아직 보존기간 내
		}
		nf, ns := PurgeCascade(p.ID)
		detail := fmt.Sprintf("자동 영구삭제(보존 %d일 초과 · findings %d · scanruns %d)", retentionDays, nf, ns)
		audit.Record("system", "system", "project:purge", p.ID, "ok", detail)
		log.Printf("[SWEEP] %s (%s) — %s", p.ID, p.Name, detail)
		purged = append(purged, p.ID)
	}
	return purged
}

// StartSweeper — 기동 시 1회 + sweepInterval(6h)마다 Sweep 실행 (goroutine, 이슈 #15).
func StartSweeper(retentionDays int) {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	log.Printf("휴지통 자동정리 스위퍼 시작: 보존 %d일, 주기 %s", retentionDays, sweepInterval)
	go func() {
		Sweep(retentionDays, time.Now())
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for range t.C {
			Sweep(retentionDays, time.Now())
		}
	}()
}
