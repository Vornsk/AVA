// Package audit — 감사 로그 (§5.1 FR-1.5). 모든 변경(누가·언제·무엇을·결과)을 기록한다.
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Entry — 감사 항목.
type Entry struct {
	Time   string `json:"time"`
	User   string `json:"user"` // 이름
	Role   string `json:"role"`
	Action string `json:"action"` // 예: project:create
	Target string `json:"target"` // 대상(프로젝트 id 등)
	Result string `json:"result"` // ok | denied
	Detail string `json:"detail,omitempty"`
}

const file = "audit.json"

var (
	mu    sync.Mutex
	log   []Entry
	clock func() time.Time = time.Now
)

// Record — 감사 항목 추가 + 파일 저장.
func Record(userName, role, action, target, result, detail string) {
	mu.Lock()
	log = append(log, Entry{
		Time: clock().Format("2006-01-02 15:04:05"),
		User: userName, Role: role, Action: action,
		Target: target, Result: result, Detail: detail,
	})
	if len(log) > 500 {
		log = log[len(log)-500:]
	}
	snapshot := append([]Entry(nil), log...)
	mu.Unlock()
	data, _ := json.MarshalIndent(snapshot, "", "  ")
	_ = os.WriteFile(file, data, 0644)
}

// List — 감사 로그 (최신이 뒤).
func List() []Entry {
	mu.Lock()
	defer mu.Unlock()
	return append([]Entry(nil), log...)
}

// Reset — 테스트용.
func Reset() {
	mu.Lock()
	log = nil
	mu.Unlock()
}
