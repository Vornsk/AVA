// Package traffic — 최근 트래픽 링버퍼 (MCP recent_requests 도구용).
// 프록시를 지나간 최근 요청을 마스킹된 형태로 최대 maxEntries개 보관.
//
//	· Log 인스턴스로 테넌트별 트래픽 로그 격리(§5.1 멀티테넌시 Phase 2).
//	  패키지 전역 함수는 기본 인스턴스(def)에 위임 → 공유 :8080 프록시 경로는 무변경.
package traffic

import "sync"

const maxEntries = 200

// Entry: 최근 요청 1건 (URL은 이미 마스킹된 값).
type Entry struct {
	Method string `json:"method"`
	URL    string `json:"url"`
}

// Log — 한 진단 컨텍스트(테넌트/공유)의 최근 트래픽 링버퍼.
type Log struct {
	mu  sync.Mutex
	buf []Entry
}

// New — 빈 트래픽 로그(테넌트별).
func New() *Log { return &Log{} }

// Record: 요청 1건 기록. URL은 마스킹된 문자열을 넣을 것.
func (l *Log) Record(method, maskedURL string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, Entry{Method: method, URL: maskedURL})
	if len(l.buf) > maxEntries {
		l.buf = l.buf[len(l.buf)-maxEntries:]
	}
}

// Recent: 최근 n건(오래된→최신). n<=0 이면 전체.
func (l *Log) Recent(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.buf) {
		n = len(l.buf)
	}
	out := make([]Entry, n)
	copy(out, l.buf[len(l.buf)-n:])
	return out
}

// Count: 현재 버퍼에 쌓인 건수.
func (l *Log) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buf)
}

// ── 기본 인스턴스 + 전역 위임 (공유 :8080 프록시 경로) ──────────────

var def = New()

// Default — 기본(전역) 트래픽 로그. 공유 프록시가 사용.
func Default() *Log { return def }

// Record — 기본 인스턴스에 위임.
func Record(method, maskedURL string) { def.Record(method, maskedURL) }

// Recent — 기본 인스턴스에 위임.
func Recent(n int) []Entry { return def.Recent(n) }

// Count — 기본 인스턴스에 위임.
func Count() int { return def.Count() }
