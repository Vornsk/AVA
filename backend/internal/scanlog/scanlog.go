// Package scanlog — 스캔 실행 중 요청 단위 실시간 로그 이벤트 (이슈 #59).
// detector 패키지는 emitter가 실렸는지도 모른 채 Emit만 호출하고(스캔 밖 호출·테스트에서는 no-op),
// scanengine이 Detect() 호출 직전에 ctx에 emitter를 실어 어느 run·detector의 이벤트인지 태깅한다.
package scanlog

import (
	"context"
	"fmt"
)

type ctxKey struct{}

// Emitter — 요청 하나가 오갈 때마다 한 줄을 흘려보내는 콜백.
type Emitter func(msg string)

// WithEmitter — ctx에 emitter를 실어 보낸다.
func WithEmitter(ctx context.Context, e Emitter) context.Context {
	return context.WithValue(ctx, ctxKey{}, e)
}

// Emit — ctx에 실린 emitter가 있으면 메시지를 흘려보낸다. 없으면 아무 일도 하지 않는다.
func Emit(ctx context.Context, format string, args ...any) {
	if e, _ := ctx.Value(ctxKey{}).(Emitter); e != nil {
		e(fmt.Sprintf(format, args...))
	}
}
