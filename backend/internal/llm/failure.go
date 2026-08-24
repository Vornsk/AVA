// 판단 실패 정책과 가시화 (이슈 #56).
//
// 프로바이더 장애는 **판단 불능**이지 **안전 판정**이 아니다. 그런데 세 실패 경로가 모두
// 조용히 통과시켰고, 그 판정이 캐시에 고착돼 프로바이더가 살아나도 돌아오지 않았다.
// 캐시 고착은 llm.go 에서 고쳤고(Degraded 는 캐시하지 않는다), 여기서 나머지 둘을 다룬다 —
//
//   - **정책 선택.** 기본은 fail-open 이다. 진단 대상의 서비스를 죽이지 않는 게 이 도구의
//     1원칙이고, 스캔 도중 ollama 가 죽었다고 진단이 통째로 멈추면 그게 더 큰 사고다.
//     다만 운영 결제계처럼 "막지 못할 바엔 보내지 않는다" 가 맞는 대상이 있으므로
//     프로젝트별로 fail-closed 를 고를 수 있게 한다.
//   - **가시화.** fail-open 이 발동해도 화면·로그는 멀쩡해 보였다(`스테이지=[rule llm]`,
//     `LLM 프로바이더: ollama`). 상태 전이를 통지해 감사 로그와 GUI 에 드러낸다.
//
// ★ 통지는 콜백으로 뺀다. 이 패키지는 내부 패키지를 하나도 import 하지 않는다(의도된 격리).
// audit 을 직접 부르면 그 격리가 깨지고 테스트에서 파일이 생긴다.
package llm

import (
	"sync"
	"time"
)

// 실패 정책.
const (
	FailOpen   = "allow" // 판단 불능 시 통과 (기본). 대상 가용성 우선
	FailClosed = "block" // 판단 불능 시 차단. 막지 못할 바엔 보내지 않는다
)

// Health — 판단 스테이지 건강 상태 (GUI·MCP 노출용).
type Health struct {
	Policy   string `json:"policy"`             // allow | block
	Degraded bool   `json:"degraded"`           // 지금 판단 불능인가
	Count    int    `json:"count"`              // 기동 후 누적 판단 불능 건수
	Reason   string `json:"reason,omitempty"`   // 마지막 실패 사유
	Since    string `json:"since,omitempty"`    // 판단 불능이 시작된 시각
	Provider string `json:"provider,omitempty"` // 그때의 프로바이더
}

var (
	fmu        sync.Mutex
	failPolicy = FailOpen
	health     Health
	notify     func(degraded bool, h Health)
)

// SetFailurePolicy — 실패 정책 지정. allow|block 외의 값은 무시하고 기본(allow)을 유지한다.
// 오타로 fail-closed 가 조용히 풀리는 것보다, 오타로 아무것도 안 바뀌는 쪽이 안전하다.
func SetFailurePolicy(p string) bool {
	if p != FailOpen && p != FailClosed {
		return false
	}
	fmu.Lock()
	failPolicy = p
	health.Policy = p
	fmu.Unlock()
	return true
}

// FailurePolicy — 현재 실패 정책.
func FailurePolicy() string {
	fmu.Lock()
	defer fmu.Unlock()
	return failPolicy
}

// SetDegradeNotifier — 판단 불능 상태가 전이될 때 부를 콜백 (감사 기록용).
// 요청마다가 아니라 **전이 시점에만** 부른다 — 장애 중 매 요청을 감사에 쓰면 audit.json 이 터진다.
func SetDegradeNotifier(f func(degraded bool, h Health)) {
	fmu.Lock()
	notify = f
	fmu.Unlock()
}

// HealthSnapshot — 현재 상태 스냅샷.
func HealthSnapshot() Health {
	fmu.Lock()
	defer fmu.Unlock()
	h := health
	h.Policy = failPolicy
	return h
}

// markDegraded — 판단 불능 1건 기록. 상태가 정상→불능으로 바뀌는 순간에만 통지한다.
func markDegraded(reason, provider string) {
	fmu.Lock()
	first := !health.Degraded
	health.Degraded = true
	health.Count++
	health.Reason = reason
	health.Provider = provider
	if first {
		health.Since = time.Now().Format("2006-01-02 15:04:05")
	}
	h, cb := health, notify
	h.Policy = failPolicy
	fmu.Unlock()
	if first && cb != nil {
		cb(true, h)
	}
}

// markHealthy — 정상 판정 1건. 불능→정상 전이에만 통지한다.
func markHealthy() {
	fmu.Lock()
	if !health.Degraded {
		fmu.Unlock()
		return
	}
	health.Degraded = false
	health.Reason, health.Since = "", ""
	h, cb := health, notify
	h.Policy = failPolicy
	fmu.Unlock()
	if cb != nil {
		cb(false, h)
	}
}

// ResetHealth — 테스트용.
func ResetHealth() {
	fmu.Lock()
	health = Health{}
	failPolicy = FailOpen
	notify = nil
	fmu.Unlock()
}
