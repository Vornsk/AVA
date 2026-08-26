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
	"proxypoc/internal/scanlog"
)

// Options — 스캔 가드레일(FR-3.2) + LLM 검토(FR-3.3).
type Options struct {
	AllowDestructive bool
	LLMReview        bool
	Inj              *auth.Injector // 인증 주입기(테넌트별). nil 이면 기본 인스턴스(§5.1 Phase 2).
	// PerTarget — endpoints.Target.Key() → 탐지기 ID 목록(override, AI 추천 HITL 검토 결과).
	// nil 이면 모든 대상에 dets 전체를 적용한다(기존 전역 스캔과 100% 동일, 하위호환).
	// 있는 대상만 좁히고, 맵에 없는 대상은 여전히 dets 전체를 쓴다(부분 override 허용).
	// 파괴성 게이트(AllowDestructive)를 통과한 집합 밖의 id는 여기서도 조용히 제외된다.
	PerTarget map[string][]string
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

// ── 실시간 로그 (이슈 #59) ──────────────────────────────────────────
// 요청 단위 이벤트를 ScanRun별 인메모리 링버퍼에 모으고, 구독자(SSE)에 그대로 흘려보낸다.
// 디스크에 저장하지 않는다 — 스캔당 수백~수천 건이라 audit.json 처럼 매번 파일에 쓰면 감당이 안 된다.

// LogEntry — 실시간 로그 한 줄 (요청 결과 또는 진행 경계 이벤트).
type LogEntry struct {
	Time     time.Time `json:"time"`
	Detector string    `json:"detector,omitempty"`
	Message  string    `json:"message"`
}

const logBufCap = 2000 // run당 보관 줄 수 상한

type logHub struct {
	mu   sync.Mutex
	buf  map[string][]LogEntry
	subs map[string]map[chan LogEntry]struct{}
}

var scanLog = &logHub{buf: map[string][]LogEntry{}, subs: map[string]map[chan LogEntry]struct{}{}}

func (h *logHub) publish(runID string, e LogEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	buf := append(h.buf[runID], e)
	if len(buf) > logBufCap {
		buf = buf[len(buf)-logBufCap:]
	}
	h.buf[runID] = buf
	for ch := range h.subs[runID] {
		select {
		case ch <- e:
		default: // 느린 구독자는 건너뛴다 — 스캔 진행을 막지 않는다
		}
	}
}

// subscribe — runID의 신규 이벤트를 받는 채널과, 구독 해제 함수를 반환.
func (h *logHub) subscribe(runID string) (chan LogEntry, func()) {
	ch := make(chan LogEntry, 64)
	h.mu.Lock()
	if h.subs[runID] == nil {
		h.subs[runID] = map[chan LogEntry]struct{}{}
	}
	h.subs[runID][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs[runID], ch)
		h.mu.Unlock()
	}
}

func (h *logHub) recent(runID string) []LogEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]LogEntry(nil), h.buf[runID]...)
}

// SubscribeLog — SSE 핸들러용: runID의 신규 로그 이벤트 채널 + 구독 해제 함수.
func SubscribeLog(runID string) (<-chan LogEntry, func()) {
	ch, cancel := scanLog.subscribe(runID)
	return ch, cancel
}

// RecentLog — runID가 지금까지 쌓아온 로그(최근 logBufCap줄). 구독 시작 시 백필용.
func RecentLog(runID string) []LogEntry {
	return scanLog.recent(runID)
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

	// 대상별 탐지기 배정: PerTarget override 가 있으면(파괴성 게이트를 통과한 used 안에서만)
	// 그 목록을, 없으면 오늘과 동일하게 used 전체를 쓴다(부분 override, 하위호환).
	byID := map[string]detector.Detector{}
	for _, d := range used {
		byID[d.ID()] = d
	}
	perTarget := make([][]detector.Detector, len(targets))
	total := 0
	for i, t := range targets {
		list := used
		if opts.PerTarget != nil {
			if ids, ok := opts.PerTarget[t.Key()]; ok {
				list = pickKnown(byID, ids)
			}
		}
		perTarget[i] = list
		total += len(list)
	}

	mu.Lock()
	seq++
	id := fmt.Sprintf("SR-%d", seq)
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{
		pid: pid,
		run: ScanRun{
			ID: id, ProjectID: pid, Status: "진행", Targets: len(targets), Detectors: usedIDs,
			Skipped: skipped, Total: total, SafeMode: safe,
		},
		ctx: ctx, cancel: cancel,
	}
	jobs[id] = j
	order = append(order, id)
	mu.Unlock()

	go j.execute(targets, perTarget, opts)
	return j.snapshot()
}

// pickKnown — id 목록을 byID(이미 파괴성 게이트를 통과한 집합)에서만 골라낸다.
// 알 수 없는/파괴적 id는 조용히 제외 — 서버 사이드 방어(프론트만 믿지 않음).
func pickKnown(byID map[string]detector.Detector, ids []string) []detector.Detector {
	var out []detector.Detector
	for _, id := range ids {
		if d, ok := byID[id]; ok {
			out = append(out, d)
		}
	}
	return out
}

func (j *job) execute(targets []endpoints.Target, perTarget [][]detector.Detector, opts Options) {
	client := &http.Client{Timeout: 15 * time.Second}
	inj := opts.Inj
	if inj == nil {
		inj = auth.Default() // 비테넌트 스캔은 기본(활성 프로젝트) 인증 상태 사용
	}
	for ti, t := range targets {
		for _, d := range perTarget[ti] {
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
			did := d.ID()
			emit := func(msg string) { scanLog.publish(j.run.ID, LogEntry{Time: time.Now(), Detector: did, Message: msg}) }
			emit(fmt.Sprintf("시작: %s %s%s", strings.Join(t.Methods, "/"), t.Host, t.Path))
			ctx := scanlog.WithEmitter(j.ctx, emit)
			var runFindings int
			for _, f := range d.Detect(ctx, t, client, inj) {
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
						ContentType: f.ContentType, // 렌더링 가능한 응답인가 (이슈 #54)
					})
					f.LLMVerdict, f.LLMReason, f.Remediation = rr.Verdict, rr.Reason, rr.Remediation
					// 주석만 — 상태는 사람이 결정(HITL). 약한 모델이 오판해도 진짜 취약을 숨기지 않는다.
					// (LLM 판정은 UI 배지/필터로 노출돼 검토를 돕는 '제안'일 뿐, 자동 조치 아니다.)
					if rr.Verdict == "false_positive" {
						j.inc(&j.run.LLMFlagged) // LLM이 오탐으로 '표시'한 건수(상태 미변경, 참고용)
					}
				}
				finding.Add(f)
				j.inc(&j.run.Findings)
				runFindings++
				emit(fmt.Sprintf("발견: %s (%s)", f.Vuln, f.Severity))
			}
			emit(fmt.Sprintf("완료: %d건 발견", runFindings))
			j.inc(&j.run.Done)
		}
	}
	j.setStatus("완료")
	persistRuns() // 완료 이력 저장 (재시작 후 유지)
	log.Printf("[SCAN] %s 완료: 대상 %d, 배정 단위 %d → finding %d개", j.run.ID, j.run.Targets, j.run.Total, j.run.Findings)
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

// DeleteByProject — 프로젝트 귀속 ScanRun 이력 제거 + 파일 갱신 (프로젝트 영구삭제 cascade, 이슈 #14).
// 반환: 지운 건수. pid 가 비면 아무것도 안 지운다(안전).
func DeleteByProject(pid string) int {
	if pid == "" {
		return 0
	}
	mu.Lock()
	kept := make([]string, 0, len(order))
	n := 0
	for _, id := range order {
		if j := jobs[id]; j != nil && j.pid == pid {
			delete(jobs, id)
			n++
			continue
		}
		kept = append(kept, id)
	}
	order = kept
	mu.Unlock()
	if n > 0 {
		persistRuns()
	}
	return n
}
