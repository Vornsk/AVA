// Package finding — 도출 항목(Finding) 저장소 (§3 Finding, finding-store).
// Detector가 낸 취약점을 저장·조회한다. 값은 마스킹된 증적만 담는다.
package finding

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const file = "findings.json"

// Finding — 도출 항목 (§3 Finding의 PoC 부분집합).
type Finding struct {
	ID         string   `json:"id"`
	ProjectID  string   `json:"project_id,omitempty"` // 귀속 프로젝트 (§5.1, §3)
	ScanRun    string   `json:"scan_run"`
	Vuln       string   `json:"vuln"`     // 취약점명
	Severity   string   `json:"severity"` // info | low | medium | high
	Host       string   `json:"host"`
	Path       string   `json:"path"`
	Method     string   `json:"method"`
	Param      string   `json:"param,omitempty"`
	Kind       string   `json:"kind"`                  // 탐지방식: rule | tool | llm
	Detector   string   `json:"detector"`              // detector id (1층)
	VulnDef    string   `json:"vuln_def,omitempty"`    // 2층 VulnDef id (§6, 예: vuln.xss)
	CheckItems []string `json:"check_items,omitempty"` // 3층 CheckItem id들(스킴별, §6)
	Confidence string   `json:"confidence"`            // 신뢰도
	Evidence   string   `json:"evidence,omitempty"`    // 근거 설명(마스킹됨)
	// 증적 (FR-4.2): 재현 요청 + 증명 응답. 값은 마스킹. 리포트·검토의 객관적 근거.
	Request  string `json:"request,omitempty"`   // 재현 요청 (METHOD URL, 마스킹)
	Response string `json:"response,omitempty"`  // 증명 응답 스니펫 (매칭 컨텍스트, 마스킹·절단)
	RespCode int    `json:"resp_code,omitempty"` // 응답 상태코드
	Status   string `json:"status"`              // 검토상태(FR-4.4): 신규 → 검토중 → 확정|오탐|보류 → 보고
	Version  int    `json:"version"`             // 낙관적 락 버전 (§5.1 FR-1.3). 수정마다 +1
	Reviewer string `json:"reviewer,omitempty"`  // 마지막 검토자 (FR-4.4)
	Time     string `json:"time,omitempty"`      // 진단일시 (§3, FR-3.5)
	// LLM 오탐 검토 (FR-3.3, §8 HITL) — 옵션
	LLMVerdict  string `json:"llm_verdict,omitempty"` // real | false_positive | uncertain
	LLMReason   string `json:"llm_reason,omitempty"`
	Remediation string `json:"remediation,omitempty"` // 조치문구
	// 이행점검 (§5.5, FR-5.3) — 옵션
	ReverifyStatus string `json:"reverify_status,omitempty"` // 조치완료 | 미조치 | 부분조치 | 신규발생
	ReverifyTime   string `json:"reverify_time,omitempty"`
}

var (
	mu    sync.Mutex
	store []Finding
	seq   int
)

// Add — finding 저장. ID를 부여한다.
func Add(f Finding) Finding {
	mu.Lock()
	seq++
	f.ID = fmt.Sprintf("F-%d", seq)
	if f.Status == "" {
		f.Status = "신규"
	}
	f.Version = 1
	if f.Time == "" {
		f.Time = time.Now().Format("2006-01-02 15:04:05")
	}
	store = append(store, f)
	snapshot := append([]Finding(nil), store...)
	mu.Unlock()

	persist(snapshot)
	return f
}

// persist — 저장소 스냅샷을 파일로 기록. (호출 시 mu 를 잡고 있지 않아야 함)
func persist(snapshot []Finding) {
	data, _ := json.MarshalIndent(snapshot, "", "  ")
	_ = os.WriteFile(file, data, 0644)
}

// Load — 저장 파일에서 finding 복원 (재시작 시 유지). 없으면 빈 상태.
// seq 를 최대 id 로 맞춰 신규 finding id(F-n) 충돌을 방지한다.
func Load() {
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}
	var loaded []Finding
	if json.Unmarshal(data, &loaded) != nil {
		return
	}
	mu.Lock()
	store = loaded
	for _, f := range loaded {
		if n := idNum(f.ID); n > seq {
			seq = n
		}
	}
	mu.Unlock()
}

// idNum — "F-<n>" 에서 n 추출 (없으면 0).
func idNum(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "F-"))
	return n
}

// ── 검토 상태머신(FR-4.4) + 낙관적 동시성(FR-1.3) ──────────────────

// ErrConflict — 낙관적 락 실패(다른 사용자가 먼저 수정). 클라이언트는 재조회 후 재시도.
var ErrConflict = errors.New("버전 충돌: 다른 사용자가 먼저 수정함")
var ErrBadTransition = errors.New("허용되지 않은 상태 전이")
var ErrNotFound = errors.New("finding 없음")

// 상태 전이 규칙 (FR-4.4). LLM 산출물은 신규로 들어와 확정 전 보고서 미포함.
var transitions = map[string][]string{
	"신규":  {"검토중", "오탐"},
	"검토중": {"확정", "오탐", "보류"},
	"보류":  {"검토중"},
	"확정":  {"보고"},
	"오탐":  {}, // 종료
	"보고":  {}, // 종료
}

// NextStates — 현재 상태에서 전이 가능한 상태들 (UI 노출용).
func NextStates(from string) []string {
	return append([]string(nil), transitions[from]...)
}

func canTransition(from, to string) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// SetStatus — 검토 상태 전이(FR-4.4) + 낙관적 락(FR-1.3). expectedVersion 이 현재와 다르면 충돌.
func SetStatus(id, to string, expectedVersion int, reviewer string) (Finding, error) {
	mu.Lock()
	var updated Finding
	var snapshot []Finding
	for i := range store {
		if store[i].ID == id {
			if store[i].Version != expectedVersion {
				f := store[i]
				mu.Unlock()
				return f, ErrConflict // 현재 상태를 함께 반환해 재조회 돕기
			}
			if !canTransition(store[i].Status, to) {
				f := store[i]
				mu.Unlock()
				return f, ErrBadTransition
			}
			store[i].Status = to
			store[i].Version++
			store[i].Reviewer = reviewer
			store[i].Time = time.Now().Format("2006-01-02 15:04:05")
			updated = store[i]
			snapshot = append([]Finding(nil), store...)
			break
		}
	}
	mu.Unlock()
	if snapshot == nil {
		return Finding{}, ErrNotFound
	}
	persist(snapshot)
	return updated, nil
}

// SetReverify — finding 의 이행점검 결과 갱신 (§5.5, FR-5.3).
func SetReverify(id, status, t string) bool {
	mu.Lock()
	found := false
	for i := range store {
		if store[i].ID == id {
			store[i].ReverifyStatus = status
			store[i].ReverifyTime = t
			found = true
			break
		}
	}
	snapshot := append([]Finding(nil), store...)
	mu.Unlock()
	if found {
		persist(snapshot)
	}
	return found
}

// Reset — 저장소 비우기 (테스트용, 파일 미변경).
func Reset() {
	mu.Lock()
	store = nil
	seq = 0
	mu.Unlock()
}

// Clear — 저장소를 비우고 파일도 빈 상태로 persist (사용자 트리거 초기화).
// 반환: 지운 건수.
func Clear() int {
	mu.Lock()
	n := len(store)
	store = nil
	seq = 0
	mu.Unlock()
	persist([]Finding{})
	return n
}

// Snapshot — 전체 finding 사본.
func Snapshot() []Finding {
	mu.Lock()
	defer mu.Unlock()
	return append([]Finding(nil), store...)
}

// ByID — id 로 finding 조회.
func ByID(id string) (Finding, bool) {
	mu.Lock()
	defer mu.Unlock()
	for _, f := range store {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

// ByScanRun — 특정 ScanRun의 finding.
func ByScanRun(id string) []Finding {
	mu.Lock()
	defer mu.Unlock()
	var out []Finding
	for _, f := range store {
		if f.ScanRun == id {
			out = append(out, f)
		}
	}
	return out
}

// ByProject — 특정 프로젝트의 finding (§5.1). pid 가 비면 전체.
func ByProject(pid string) []Finding {
	mu.Lock()
	defer mu.Unlock()
	if pid == "" {
		return append([]Finding(nil), store...)
	}
	var out []Finding
	for _, f := range store {
		if f.ProjectID == pid {
			out = append(out, f)
		}
	}
	return out
}

// DeleteByProject — 프로젝트 귀속 finding 제거 + 파일 갱신 (프로젝트 영구삭제 cascade, 이슈 #14).
// 반환: 지운 건수. pid 가 비면 아무것도 안 지운다(안전).
func DeleteByProject(pid string) int {
	if pid == "" {
		return 0
	}
	mu.Lock()
	kept := make([]Finding, 0, len(store))
	n := 0
	for _, f := range store {
		if f.ProjectID == pid {
			n++
			continue
		}
		kept = append(kept, f)
	}
	store = kept
	snap := append([]Finding(nil), store...)
	mu.Unlock()
	if n > 0 {
		persist(snap)
	}
	return n
}
