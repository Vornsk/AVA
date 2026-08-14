// Package reverify — 이행점검 (§5.5). 취약 판정 finding 만 선별해(FR-5.1) 재현 컨텍스트를
// replay 하고(FR-5.2) 원래 탐지기로 재평가해 조치 여부를 판정한다(FR-5.3). 또한 ScanRun 간
// 공격면 변화(신규/소멸 finding)를 비교한다(FR-5.4). 전체 재스캔이 아니라 대상 finding 만 재현.
package reverify

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/detector"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/finding"
)

// 판정값 (FR-5.3).
const (
	VerdictFixed   = "조치완료" // 재현 안 됨
	VerdictOpen    = "미조치"  // 여전히 재현됨
	VerdictPartial = "부분조치" // 일부만 재현 (다중 인스턴스)
	VerdictNew     = "신규발생" // 재점검 중 새로 발견
	VerdictUnknown = "미확인"  // 자동 재현 불가(탐지기 없음 → 수동)
)

// ItemResult — finding 1건의 재점검 결과.
type ItemResult struct {
	FindingID  string `json:"finding_id"`
	Vuln       string `json:"vuln"`
	VulnDef    string `json:"vuln_def,omitempty"` // 2층 VulnDef id (화면 로케일용, #18)
	Target     string `json:"target"`
	Detector   string `json:"detector"`
	Verdict    string `json:"verdict"`
	Reproduced bool   `json:"reproduced"`
	Detail     string `json:"detail,omitempty"`
	Time       string `json:"time"`
}

// Run — 이행점검 실행 단위.
type Run struct {
	ID      string       `json:"id"`
	Source  string       `json:"source"` // 대상 ScanRun id 또는 "all"
	Total   int          `json:"total"`
	Fixed   int          `json:"fixed"`   // 조치완료
	Open    int          `json:"open"`    // 미조치
	Unknown int          `json:"unknown"` // 미확인(수동)
	Results []ItemResult `json:"results"`
	Time    string       `json:"time"`
}

var (
	mu   sync.Mutex
	runs []Run
	seq  int
)

// Reverify — 취약 finding 들을 replay·재평가(FR-5.2/5.3). source 는 표시용 라벨.
func Reverify(ctx context.Context, items []finding.Finding, source string) Run {
	client := &http.Client{Timeout: 15 * time.Second}
	now := time.Now().Format("2006-01-02 15:04:05")

	mu.Lock()
	seq++
	id := fmt.Sprintf("RV-%d", seq)
	mu.Unlock()

	run := Run{ID: id, Source: source, Time: now}
	for _, f := range items {
		res := ItemResult{
			FindingID: f.ID, Vuln: f.Vuln, VulnDef: f.VulnDef, Target: f.Host + f.Path,
			Detector: f.Detector, Time: now,
		}
		dets := detector.Select([]string{f.Detector})
		if len(dets) == 0 {
			res.Verdict = VerdictUnknown
			res.Detail = "탐지기 없음 → 수동 재점검 필요"
			run.Unknown++
		} else {
			got := dets[0].Detect(ctx, targetFor(f), client, auth.Default())
			res.Reproduced = len(got) > 0
			if res.Reproduced {
				res.Verdict = VerdictOpen
				res.Detail = fmt.Sprintf("재현됨 (%d건)", len(got))
				run.Open++
			} else {
				res.Verdict = VerdictFixed
				res.Detail = "재현 안 됨"
				run.Fixed++
			}
			finding.SetReverify(f.ID, res.Verdict, now) // 타임라인 갱신 (FR-5.3)
		}
		run.Total++
		run.Results = append(run.Results, res)
	}

	mu.Lock()
	runs = append(runs, run)
	mu.Unlock()
	return run
}

// targetFor — finding 의 재현 컨텍스트를 스캔 대상으로 복원 (FR-5.2).
func targetFor(f finding.Finding) endpoints.Target {
	t := endpoints.Target{Host: f.Host, Path: f.Path}
	if f.Method != "" {
		t.Methods = []string{f.Method}
	}
	if f.Param != "" {
		t.Params = []endpoints.Param{{Name: f.Param, In: "query"}}
	}
	// 접근통제/IDOR 계열은 인증 동반 엔드포인트로 복원.
	if f.Detector == "idor" {
		t.Auth = true
	}
	return t
}

// Runs — 지금까지의 이행점검 실행들.
func Runs() []Run {
	mu.Lock()
	defer mu.Unlock()
	return append([]Run(nil), runs...)
}

// ── FR-5.4 스캔 간 diff (공격면 변화) ──────────────────────────────

// Diff — 두 ScanRun 의 finding 집합 비교 결과.
type Diff struct {
	From    string            `json:"from"`
	To      string            `json:"to"`
	Added   []finding.Finding `json:"added"`   // To 에만 (신규 취약점)
	Removed []finding.Finding `json:"removed"` // From 에만 (소멸)
	Common  int               `json:"common"`
}

func findingKey(f finding.Finding) string {
	return f.Vuln + "|" + f.Host + f.Path + "|" + f.Method + "|" + f.Param
}

// DiffRuns — from→to ScanRun 사이 신규/소멸 finding 을 계산 (FR-5.4).
func DiffRuns(from, to string) Diff {
	a := finding.ByScanRun(from)
	b := finding.ByScanRun(to)
	ak := map[string]bool{}
	for _, f := range a {
		ak[findingKey(f)] = true
	}
	bk := map[string]bool{}
	for _, f := range b {
		bk[findingKey(f)] = true
	}
	d := Diff{From: from, To: to, Added: []finding.Finding{}, Removed: []finding.Finding{}}
	for _, f := range b {
		if !ak[findingKey(f)] {
			d.Added = append(d.Added, f)
		} else {
			d.Common++
		}
	}
	for _, f := range a {
		if !bk[findingKey(f)] {
			d.Removed = append(d.Removed, f)
		}
	}
	return d
}
