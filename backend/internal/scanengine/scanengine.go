// Package scanengine — 진단 오케스트레이션 (§5.3 scan-engine, ScanRun).
// 스캔은 비동기 잡(FR-3.8): 진행률·일시정지·재개·취소를 지원하고, 긴급 kill switch(FR-3.2)로
// 전체 중단한다. 파괴성 가드레일(FR-3.2)·LLM 오탐검토(FR-3.3)도 여기서 적용.
package scanengine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/checklist"
	"proxypoc/internal/detector"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/finding"
	"proxypoc/internal/llm"
	"proxypoc/internal/project"
)

// Options — 스캔 가드레일(FR-3.2) + LLM 검토(FR-3.3).
type Options struct {
	AllowDestructive bool
	LLMReview        bool
	Inj              *auth.Injector // 인증 주입기(테넌트별). nil 이면 기본 인스턴스(§5.1 Phase 2).
}

// ScanRun — 진단 실행 단위 (§3 ScanRun). 진행률·상태 포함(FR-3.8).
type ScanRun struct {
	ID         string   `json:"id"`
	ProjectID  string   `json:"project_id,omitempty"` // 귀속 프로젝트 (§5.1, §3)
	Status     string   `json:"status"`               // 진행 | 일시정지 | 완료 | 중단
	Targets    int      `json:"targets"`
	Detectors  []string `json:"detectors"`
	Skipped    []string `json:"skipped,omitempty"` // 가드레일로 제외
	Total      int      `json:"total"`             // 총 (탐지기×대상) 단위
	Done       int      `json:"done"`              // 완료 단위
	Findings   int      `json:"findings"`
	LLMFlagged int      `json:"llm_flagged,omitempty"` // LLM이 오탐으로 '표시'한 건수(상태 미변경, 검토 참고용)
	SafeMode   bool     `json:"safe_mode,omitempty"`   // 안전모드로 실행됨 (FR-3.2)
}

var (
	safeMu   sync.Mutex
	safeMode bool
)

// SetSafeMode — 안전모드 토글 (FR-3.2). 켜면 파괴성 강제 제외 + 요청 간격 강화.
func SetSafeMode(on bool) {
	safeMu.Lock()
	safeMode = on
	safeMu.Unlock()
	if on {
		detector.SetRateGap(500 * time.Millisecond)
	} else {
		detector.SetRateGap(150 * time.Millisecond)
	}
}

// SafeMode — 현재 안전모드 상태.
func SafeMode() bool {
	safeMu.Lock()
	defer safeMu.Unlock()
	return safeMode
}

type job struct {
	mu     sync.Mutex
	pid    string // 귀속 프로젝트 id (§5.1)
	run    ScanRun
	paused bool
	ctx    context.Context
	cancel context.CancelFunc
}

var (
	mu    sync.Mutex
	jobs  = map[string]*job{}
	order []string
	seq   int
)

// Start — 비동기 스캔 시작. 즉시 진행중 ScanRun을 반환(FR-3.8).
func Start(targets []endpoints.Target, dets []detector.Detector, opts Options) ScanRun {
	safe := SafeMode()
	if safe {
		opts.AllowDestructive = false // 안전모드: 파괴성 강제 제외 (FR-3.2)
	}
	var used []detector.Detector
	var usedIDs, skipped []string
	for _, d := range dets {
		if d.Destructive() && !opts.AllowDestructive {
			skipped = append(skipped, d.ID()) // 가드레일: 파괴성 기본 제외
			continue
		}
		used = append(used, d)
		usedIDs = append(usedIDs, d.ID())
	}

	pid := ""
	if p, ok := project.Active(); ok {
		pid = p.ID // 귀속 프로젝트 (§5.1)
	}

	mu.Lock()
	seq++
	id := fmt.Sprintf("SR-%d", seq)
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{
		pid: pid,
		run: ScanRun{
			ID: id, ProjectID: pid, Status: "진행", Targets: len(targets), Detectors: usedIDs,
			Skipped: skipped, Total: len(used) * len(targets), SafeMode: safe,
		},
		ctx: ctx, cancel: cancel,
	}
	jobs[id] = j
	order = append(order, id)
	mu.Unlock()

	go j.execute(targets, used, opts)
	return j.snapshot()
}

func (j *job) execute(targets []endpoints.Target, dets []detector.Detector, opts Options) {
	client := &http.Client{Timeout: 15 * time.Second}
	inj := opts.Inj
	if inj == nil {
		inj = auth.Default() // 비테넌트 스캔은 기본(활성 프로젝트) 인증 상태 사용
	}
	for _, d := range dets {
		for _, t := range targets {
			if j.ctx.Err() != nil {
				j.setStatus("중단")
				return
			}
			for j.isPaused() { // 일시정지 대기 (FR-3.8)
				if j.ctx.Err() != nil {
					j.setStatus("중단")
					return
				}
				time.Sleep(150 * time.Millisecond)
			}
			for _, f := range d.Detect(j.ctx, t, client, inj) {
				f.ScanRun = j.run.ID
				f.ProjectID = j.pid // 귀속 프로젝트 (§5.1)
				// 점검항목표 연결 (§6): detector → VulnDef/CheckItem 태깅.
				if vulns, items := checklist.MapDetector(f.Detector); len(vulns) > 0 || len(items) > 0 {
					if len(vulns) > 0 {
						f.VulnDef = vulns[0]
					}
					f.CheckItems = items
				}
				if opts.LLMReview {
					rr := llm.Review(j.ctx, llm.ReviewInput{
						Vuln: f.Vuln, Severity: f.Severity, Method: f.Method,
						Path: f.Path, Param: f.Param, Detector: f.Detector, Evidence: f.Evidence,
						Request: f.Request, Response: f.Response, RespCode: f.RespCode, // 실제 증적으로 문맥 판단
					})
					f.LLMVerdict, f.LLMReason, f.Remediation = rr.Verdict, rr.Reason, rr.Remediation
					// 주석만 — 상태는 사람이 결정(HITL). 약한 모델이 오판해도 진짜 취약을 숨기지 않는다.
					// (LLM 판정은 UI 배지/필터로 노출돼 검토를 돕는 '제안'일 뿐, 자동 조치 아님.)
					if rr.Verdict == "false_positive" {
						j.inc(&j.run.LLMFlagged) // LLM이 오탐으로 '표시'한 건수(상태 미변경, 참고용)
					}
				}
				finding.Add(f)
				j.inc(&j.run.Findings)
			}
			j.inc(&j.run.Done)
		}
	}
	j.setStatus("완료")
	persistRuns() // 완료 이력 저장 (재시작 후 유지)
	log.Printf("[SCAN] %s 완료: 대상 %d × 탐지기 %d → finding %d개", j.run.ID, j.run.Targets, len(dets), j.run.Findings)
}

// ── 잡 제어 (FR-3.8) ──────────────────────────────────────────────

func (j *job) snapshot() ScanRun { j.mu.Lock(); defer j.mu.Unlock(); return j.run }
func (j *job) isPaused() bool    { j.mu.Lock(); defer j.mu.Unlock(); return j.paused }
func (j *job) inc(p *int)        { j.mu.Lock(); *p++; j.mu.Unlock() }
func (j *job) setStatus(s string) {
	j.mu.Lock()
	if j.run.Status != "완료" && j.run.Status != "중단" {
		j.run.Status = s
	}
	j.mu.Unlock()
}

func get(id string) *job {
	mu.Lock()
	defer mu.Unlock()
	return jobs[id]
}

// Status — 잡 상태 조회.
func Status(id string) (ScanRun, bool) {
	if j := get(id); j != nil {
		return j.snapshot(), true
	}
	return ScanRun{}, false
}

// Pause — 진행중 잡 일시정지.
func Pause(id string) bool {
	j := get(id)
	if j == nil {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.run.Status == "진행" {
		j.paused = true
		j.run.Status = "일시정지"
		return true
	}
	return false
}

// Resume — 일시정지 잡 재개.
func Resume(id string) bool {
	j := get(id)
	if j == nil {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.run.Status == "일시정지" {
		j.paused = false
		j.run.Status = "진행"
		return true
	}
	return false
}

// Cancel — 잡 취소(중단). 이미 완료·중단된 잡이면 no-op으로 false(멱등, FR-3.8).
func Cancel(id string) bool {
	j := get(id)
	if j == nil {
		return false
	}
	j.mu.Lock()
	if j.run.Status == "완료" || j.run.Status == "중단" {
		j.mu.Unlock()
		return false
	}
	j.mu.Unlock()
	j.cancel()
	j.setStatus("중단")
	persistRuns()
	return true
}

// KillAll — 진행중 모든 잡 긴급 중단 (FR-3.2 kill switch). 중단 수 반환.
func KillAll() int {
	mu.Lock()
	all := make([]*job, 0, len(jobs))
	for _, j := range jobs {
		all = append(all, j)
	}
	mu.Unlock()
	n := 0
	for _, j := range all {
		s := j.snapshot().Status
		if s == "진행" || s == "일시정지" {
			j.cancel()
			j.setStatus("중단")
			n++
		}
	}
	if n > 0 {
		persistRuns()
	}
	return n
}

// ── 영속화 (완료/중단 이력 유지) ──────────────────────────────────
const runsFile = "scanruns.json"

// persistRuns — 현재 ScanRun 이력을 파일로 기록 (터미널 전이 시 호출).
func persistRuns() {
	data, _ := json.MarshalIndent(Runs(), "", "  ")
	_ = os.WriteFile(runsFile, data, 0644)
}

// Load — 저장된 ScanRun 이력 복원 (완료/중단). 라이브 실행 상태·취소는 미복원.
// seq 를 최대 SR-n 으로 맞춰 신규 run id 충돌을 방지한다.
func Load() {
	data, err := os.ReadFile(runsFile)
	if err != nil {
		return
	}
	var runs []ScanRun
	if json.Unmarshal(data, &runs) != nil {
		return
	}
	mu.Lock()
	for _, sr := range runs {
		if _, exists := jobs[sr.ID]; exists {
			continue
		}
		jobs[sr.ID] = &job{pid: sr.ProjectID, run: sr, cancel: func() {}} // 복원 잡: no-op cancel
		order = append(order, sr.ID)
		if n := runNum(sr.ID); n > seq {
			seq = n
		}
	}
	mu.Unlock()
}

func runNum(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "SR-"))
	return n
}

// Runs — 모든 ScanRun 스냅샷 (생성 순).
func Runs() []ScanRun {
	mu.Lock()
	ids := append([]string(nil), order...)
	mu.Unlock()
	out := make([]ScanRun, 0, len(ids))
	for _, id := range ids {
		if j := get(id); j != nil {
			out = append(out, j.snapshot())
		}
	}
	return out
}

// RunsByProject — 특정 프로젝트의 ScanRun (§5.1). pid 가 비면 전체.
func RunsByProject(pid string) []ScanRun {
	all := Runs()
	if pid == "" {
		return all
	}
	out := make([]ScanRun, 0, len(all))
	for _, r := range all {
		if r.ProjectID == pid {
			out = append(out, r)
		}
	}
	return out
}
