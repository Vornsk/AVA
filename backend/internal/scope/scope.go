// Package scope — 진단 대상 스코프 강제 (FR-2.1 최우선).
// 화이트리스트 밖 도메인/경로는 차단(하드 스코프). 제외 목록도 지원.
//
//	· 호스트 화이트리스트 (정확/서브도메인)
//	· 경로 허용 목록(allowPaths): 비면 모든 경로 허용, 있으면 매칭만 허용
//	· 경로 제외 목록(excludePaths): 매칭되면 차단(허용보다 우선)
//
// CONNECT 단계는 host만, 요청 단계는 host+path 종합 판단.
//
// 멀티테넌시(§5.1): Enforcer 인스턴스로 프로젝트별 스코프를 분리한다. 패키지 전역 함수는
// 기본 Enforcer(def, :8080 공유 프록시용)에 위임한다.
package scope

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// Enforcer — 한 테넌트(프로젝트)의 스코프 상태.
type Enforcer struct {
	mu        sync.RWMutex
	hosts     []string
	allowRe   []*regexp.Regexp
	excludeRe []*regexp.Regexp
}

// New — 스코프 Enforcer 생성 (프로젝트별 테넌트용).
func New(hosts, allowPaths, excludePaths []string) *Enforcer {
	e := &Enforcer{}
	e.Configure(hosts, allowPaths, excludePaths)
	return e
}

func (e *Enforcer) Configure(h, allowPaths, excludePaths []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hosts = cleanHosts(h)
	e.allowRe = compile(allowPaths)
	e.excludeRe = compile(excludePaths)
}

func (e *Enforcer) InScope(host string) bool {
	host = strings.ToLower(host)
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.hostMatch(host)
}

func (e *Enforcer) Allowed(host, path string) (bool, string) {
	host = strings.ToLower(host)
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.hostMatch(host) {
		return false, "스코프 밖 도메인"
	}
	for _, re := range e.excludeRe {
		if re.MatchString(path) {
			return false, "제외 경로"
		}
	}
	if len(e.allowRe) > 0 {
		ok := false
		for _, re := range e.allowRe {
			if re.MatchString(path) {
				ok = true
				break
			}
		}
		if !ok {
			return false, "허용 경로 아님"
		}
	}
	return true, ""
}

func (e *Enforcer) hostMatch(host string) bool { // 호출자가 락 보유
	for _, a := range e.hosts {
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

func (e *Enforcer) Add(h string) bool {
	h = NormalizeHost(h) // 관용 입력 허용 (URL 통째로 넣어도 호스트만)
	if h == "" {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, a := range e.hosts {
		if a == h {
			return false
		}
	}
	e.hosts = append(e.hosts, h)
	return true
}

func (e *Enforcer) Remove(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, a := range e.hosts {
		if a == h {
			e.hosts = append(e.hosts[:i], e.hosts[i+1:]...)
			return true
		}
	}
	return false
}

func (e *Enforcer) Snapshot() Info {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return Info{
		Hosts:        append([]string(nil), e.hosts...),
		AllowPaths:   patterns(e.allowRe),
		ExcludePaths: patterns(e.excludeRe),
	}
}

func (e *Enforcer) HostsSnapshot() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]string(nil), e.hosts...)
}

// Info — 스코프 조회 결과 (MCP get_scope).
type Info struct {
	Hosts        []string `json:"hosts"`
	AllowPaths   []string `json:"allow_paths,omitempty"`
	ExcludePaths []string `json:"exclude_paths,omitempty"`
}

// ── 기본 Enforcer(전역) + 위임 함수 (하위호환, :8080 공유 프록시) ──

var def = &Enforcer{}

// Default — 기본(전역) Enforcer.
func Default() *Enforcer { return def }

func Configure(h, allowPaths, excludePaths []string) { def.Configure(h, allowPaths, excludePaths) }
func InScope(host string) bool                       { return def.InScope(host) }
func Allowed(host, path string) (bool, string)       { return def.Allowed(host, path) }
func Add(h string) bool                              { return def.Add(h) }
func Remove(h string) bool                           { return def.Remove(h) }
func Snapshot() Info                                 { return def.Snapshot() }
func HostsSnapshot() []string                        { return def.HostsSnapshot() }

// HostOnly — "example.com:443" → "example.com"
func HostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// ── 헬퍼 ──────────────────────────────────────────────────────────

func cleanHosts(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		if h = NormalizeHost(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// NormalizeHost — 스코프 입력을 호스트명 하나로 정규화한다 (관용 입력 허용).
//
// 스코프는 호스트 화이트리스트인데, 사용자가 "http://192.168.100.5/" 처럼 URL 을 통째로
// 넣으면 hostMatch(요청의 u.Hostname() 과 문자열 비교)가 영영 어긋나 크롤·프록시가 전부
// "스코프 밖" 으로 버려진다 — 링크를 다 찾고도 엔드포인트 0개가 되는 함정. 그래서 스킴·경로·
// 포트를 벗겨 호스트만 남긴다. 어느 형식으로 넣어도 동작하게 만드는 게 목적이다.
//
//	http://192.168.100.5/           → 192.168.100.5
//	https://example.com/path?q=1    → example.com
//	example.com:8080                → example.com   (hostMatch 는 포트를 안 보므로 제거)
//	EXAMPLE.com                     → example.com
func NormalizeHost(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	probe := s
	if !strings.Contains(probe, "//") { // 스킴 없으면 url.Parse 가 호스트로 인식하도록
		probe = "//" + probe
	}
	if u, err := url.Parse(probe); err == nil {
		if h := u.Hostname(); h != "" {
			return strings.ToLower(h)
		}
	}
	// 폴백: 경로 자르고 포트 제거
	if i := strings.IndexAny(s, `/\?`); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.ToLower(s)
}

func compile(pats []string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, p := range pats {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if re, err := regexp.Compile(p); err == nil {
			out = append(out, re)
		}
	}
	return out
}

func patterns(res []*regexp.Regexp) []string {
	out := make([]string, 0, len(res))
	for _, re := range res {
		out = append(out, re.String())
	}
	return out
}
