// Package auth — 인증 크롤링: 세션/쿠키·인증 헤더 주입 (FR-2.5).
// in-scope 요청에 설정된 인증정보를 주입해 "로그인된 신원"으로 진단하게 한다.
//
//	· 값은 민감정보 → 로그·MCP에는 키만 노출(Snapshot), 원문은 안 남긴다.
//	· 실제 제품은 서버 암호화 보관(FR-1.4). PoC는 project.config.yaml 평문(주의).
//	· 다중 신원(FR-3.6)은 identity 목록으로 확장.
//	· Injector 인스턴스로 테넌트별 인증상태 격리(§5.1 멀티테넌시 Phase 2).
//	  패키지 전역 함수는 기본 인스턴스(def)에 위임 → 단일 프로젝트 경로는 무변경.
package auth

import (
	"net/http"
	"regexp"
	"sync"
	"time"
)

// Config — 주입할 인증정보.
type Config struct {
	Cookies map[string]string `yaml:"cookies" json:"cookies"`
	Headers map[string]string `yaml:"headers" json:"headers"`
	Admin   bool              `yaml:"admin" json:"admin,omitempty"` // identities 항목에서만: 고권한(관리자) 신원 표시
}

// Injector — 한 진단 컨텍스트(테넌트/프로젝트)의 인증 주입 상태.
// 크롤 요청에 주입할 기본 인증정보(cfg)와 다중 신원 목록(identities)을 담는다.
type Injector struct {
	mu         sync.RWMutex
	cfg        Config
	identities []Identity

	// 세션 지속성(session.go): 만료 시 자동 재로그인.
	login     LoginSeq
	loginRe   *regexp.Regexp
	loginMu   sync.Mutex // 재로그인 단일 실행
	lastLogin time.Time
}

// New — 빈 Injector (테넌트별 인증상태).
func New() *Injector { return &Injector{} }

// Set — 주입 인증정보 지정.
func (in *Injector) Set(c Config) {
	in.mu.Lock()
	in.cfg = c
	in.mu.Unlock()
}

// Enabled — 주입할 인증정보가 있는가.
func (in *Injector) Enabled() bool {
	in.mu.RLock()
	defer in.mu.RUnlock()
	return len(in.cfg.Cookies) > 0 || len(in.cfg.Headers) > 0
}

// Inject — 설정된 쿠키/헤더를 요청에 주입. (in-scope 통과 요청에만 호출할 것)
func (in *Injector) Inject(req *http.Request) {
	in.mu.RLock()
	defer in.mu.RUnlock()
	for k, v := range in.cfg.Headers {
		req.Header.Set(k, v)
	}
	for name, val := range in.cfg.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: val})
	}
}

// Snapshot — 설정 조회용(마스킹). 값은 가리고 키만 노출.
func (in *Injector) Snapshot() map[string][]string {
	in.mu.RLock()
	defer in.mu.RUnlock()
	cookies := make([]string, 0, len(in.cfg.Cookies))
	for k := range in.cfg.Cookies {
		cookies = append(cookies, k)
	}
	headers := make([]string, 0, len(in.cfg.Headers))
	for k := range in.cfg.Headers {
		headers = append(headers, k)
	}
	return map[string][]string{"cookies": cookies, "headers": headers}
}

// SetIdentities — 등록 신원 지정.
func (in *Injector) SetIdentities(ids []Identity) {
	in.mu.Lock()
	in.identities = ids
	in.mu.Unlock()
}

// Identities — 비교 대상 신원 목록. 항상 맨 앞에 비인가(anon)를 포함한다.
func (in *Injector) Identities() []Identity {
	in.mu.RLock()
	defer in.mu.RUnlock()
	out := make([]Identity, 0, len(in.identities)+1)
	out = append(out, Identity{Name: "anon"})
	out = append(out, in.identities...)
	return out
}

// IdentityNames — 등록 신원 이름 (anon 포함, 값 노출 없음).
func (in *Injector) IdentityNames() []string {
	in.mu.RLock()
	defer in.mu.RUnlock()
	out := []string{"anon"}
	for _, id := range in.identities {
		out = append(out, id.Name)
	}
	return out
}

// ── 기본 인스턴스 + 전역 위임 (단일 프로젝트·공유 프록시 경로) ──────────

var def = New()

// Default — 기본(전역) Injector. 공유 :8080 프록시·비테넌트 스캔이 사용.
func Default() *Injector { return def }

// Set — 기본 인스턴스에 위임.
func Set(c Config) { def.Set(c) }

// Enabled — 기본 인스턴스에 위임.
func Enabled() bool { return def.Enabled() }

// Inject — 기본 인스턴스에 위임.
func Inject(req *http.Request) { def.Inject(req) }

// Snapshot — 기본 인스턴스에 위임.
func Snapshot() map[string][]string { return def.Snapshot() }

// SetIdentities — 기본 인스턴스에 위임.
func SetIdentities(ids []Identity) { def.SetIdentities(ids) }

// Identities — 기본 인스턴스에 위임.
func Identities() []Identity { return def.Identities() }

// IdentityNames — 기본 인스턴스에 위임.
func IdentityNames() []string { return def.IdentityNames() }

// SetLogin — 기본 인스턴스에 위임(세션 지속성).
func SetLogin(s LoginSeq) { def.SetLogin(s) }

// LoginSnapshot — 기본 인스턴스에 위임(마스킹 조회).
func LoginSnapshot() LoginInfo { return def.LoginSnapshot() }
