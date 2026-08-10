// Package tenant — 프록시 엔진 멀티테넌시 (§5.1 FR-1.1, Phase 1).
// 프로젝트별로 전용 프록시 인스턴스를 별도 포트에 띄우고, 각자 격리된 스코프 Enforcer 와
// 엔드포인트 Tree 를 갖는다 → 두 프로젝트를 동시에 진단해도 캡처가 섞이지 않는다.
// 기본 :8080 공유 프록시(전역 상태)는 그대로 유지된다.
// (Phase 2: traffic·auth 도 테넌트별로 분리, 스캔엔진의 테넌트 대상화)
package tenant

import (
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/project"
	"proxypoc/internal/proxyengine"
	"proxypoc/internal/scope"
	"proxypoc/internal/traffic"
)

// Tenant — 한 프로젝트의 격리된 프록시 인스턴스.
type Tenant struct {
	ProjectID string
	Port      int
	Started   string
	scope     *scope.Enforcer
	tree      *endpoints.Tree
	inj       *auth.Injector
	traffic   *traffic.Log
	server    *http.Server
}

// Info — API 노출용 요약.
type Info struct {
	ProjectID string   `json:"project_id"`
	Port      int      `json:"port"`
	Scope     []string `json:"scope"`
	Endpoints int      `json:"endpoints"`
	Traffic   int      `json:"traffic"` // 이 테넌트가 지나보낸 요청 수 (격리)
	Started   string   `json:"started"`
}

var (
	mu      sync.Mutex
	tenants = map[string]*Tenant{}
	stages  = []string{"rule", "llm"} // 판단 스테이지 (main 에서 설정)
)

// SetStages — 판단 파이프라인 스테이지 (기동 시 config 기반).
func SetStages(s []string) {
	if len(s) > 0 {
		stages = append([]string(nil), s...)
	}
}

func (t *Tenant) info() Info {
	return Info{
		ProjectID: t.ProjectID, Port: t.Port,
		Scope:     t.scope.HostsSnapshot(),
		Endpoints: len(t.tree.Targets()),
		Traffic:   t.traffic.Count(),
		Started:   t.Started,
	}
}

// Start — 프로젝트용 테넌트 프록시 기동(이미 있으면 그대로 반환).
func Start(pid string) (Info, error) {
	mu.Lock()
	if t, ok := tenants[pid]; ok {
		info := t.info()
		mu.Unlock()
		return info, nil
	}
	mu.Unlock()

	p, ok := project.Get(pid)
	if !ok {
		return Info{}, errNotFound{pid}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0") // OS 할당 포트(충돌 방지)
	if err != nil {
		return Info{}, err
	}
	port := ln.Addr().(*net.TCPAddr).Port

	sc := scope.New(p.Scope, p.AllowPaths, p.ExcludePaths)
	tr := endpoints.NewTree()
	inj := auth.New() // 테넌트 전용 인증 상태 (전역/타 프로젝트와 격리, §5.1 Phase 2)
	if cfg, ids, ok := project.CredsToAuth(pid); ok {
		inj.Set(cfg)
		inj.SetIdentities(ids)
	}
	tl := traffic.New() // 테넌트 전용 트래픽 로그 (격리)
	proxy := proxyengine.NewFor(stages, sc, tr, inj, tl, pid)
	srv := &http.Server{Handler: proxy}

	t := &Tenant{
		ProjectID: pid, Port: port, Started: time.Now().Format("2006-01-02 15:04:05"),
		scope: sc, tree: tr, inj: inj, traffic: tl, server: srv,
	}
	go func() { _ = srv.Serve(ln) }()

	mu.Lock()
	tenants[pid] = t
	mu.Unlock()
	log.Printf("[TENANT] 프록시 시작: %s → 127.0.0.1:%d  scope=%v", pid, port, p.Scope)
	return t.info(), nil
}

// Stop — 테넌트 프록시 종료.
func Stop(pid string) bool {
	mu.Lock()
	t, ok := tenants[pid]
	if ok {
		delete(tenants, pid)
	}
	mu.Unlock()
	if !ok {
		return false
	}
	_ = t.server.Close()
	log.Printf("[TENANT] 프록시 종료: %s (:%d)", pid, t.Port)
	return true
}

// List — 실행 중 테넌트 요약.
func List() []Info {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Info, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, t.info())
	}
	return out
}

// Endpoints — 특정 테넌트가 캡처한 엔드포인트 트리 (격리 확인용).
func Endpoints(pid string) ([]endpoints.OutNode, bool) {
	mu.Lock()
	t, ok := tenants[pid]
	mu.Unlock()
	if !ok {
		return nil, false
	}
	return t.tree.Snapshot(), true
}

// Traffic — 특정 테넌트가 지나보낸 최근 트래픽 (격리 확인용).
func Traffic(pid string, n int) ([]traffic.Entry, bool) {
	mu.Lock()
	t, ok := tenants[pid]
	mu.Unlock()
	if !ok {
		return nil, false
	}
	return t.traffic.Recent(n), true
}

type errNotFound struct{ id string }

func (e errNotFound) Error() string { return "project 없음: " + e.id }
