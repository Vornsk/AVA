// control.go — 공용 프록시(:8080) 런타임 제어·상태 (이슈 #5).
// 프록시 프로세스는 항상 켜진 채로 두고, "엔드포인트 캡처(공격면 기록)"만 on/off 한다.
// 스코프 강제·인증 주입·판단 파이프라인은 캡처 상태와 무관하게 그대로 동작한다.
package proxyengine

import "sync/atomic"

var (
	captureOn    atomic.Bool   // 공용 프록시 엔드포인트 캡처 on/off (기본 on)
	capturedReqs atomic.Uint64 // 캡처 on 상태에서 공용 트리에 기록된 누적 요청 수
	listenAddr   atomic.Value  // string — 공용 프록시 리슨 주소 (상태 조회용)
)

func init() { captureOn.Store(true) }

// SetCapture — 공용 프록시의 엔드포인트 캡처를 켜고 끈다. 프로세스·스코프·인증·판단은 영향 없음.
func SetCapture(on bool) { captureOn.Store(on) }

// CaptureEnabled — 현재 캡처 상태.
func CaptureEnabled() bool { return captureOn.Load() }

// CapturedCount — 캡처 on 상태에서 공용 트리에 기록된 누적 요청 수(부팅 이후).
func CapturedCount() uint64 { return capturedReqs.Load() }

// SetListenAddr — 공용 프록시 리슨 주소 설정 (main 기동 시).
func SetListenAddr(a string) { listenAddr.Store(a) }

// ListenAddr — 공용 프록시 리슨 주소. 미설정이면 "".
func ListenAddr() string {
	if v, ok := listenAddr.Load().(string); ok {
		return v
	}
	return ""
}
