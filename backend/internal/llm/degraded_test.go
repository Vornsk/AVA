package llm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// 이슈 #56 — 프로바이더 장애가 전건 허용으로 흡수되고 그 판정이 캐시에 고착되던 문제.

// flappy — 앞의 n회는 실패하고 그 뒤로 정상 응답하는 스텁. 프로바이더가 죽었다 살아나는 상황.
type flappy struct {
	mu       sync.Mutex
	calls    int
	failNext int
	reply    string
}

func (f *flappy) Name() string { return "flappy" }

func (f *flappy) Complete(context.Context, string, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failNext > 0 {
		f.failNext--
		return "", errors.New("dial tcp 127.0.0.1:59999: connectex: No connection could be made")
	}
	if f.reply == "" {
		return `{"allow":false,"reason":"위험","confidence":0.9}`, nil
	}
	return f.reply, nil
}

func (f *flappy) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// ★ 이 이슈의 핵심. 프로바이더가 죽어 있는 동안의 통과 판정을 캐시하면, 살아난 뒤에도
// 같은 시그니처는 프로세스가 사는 동안 계속 통과한다 — 가드레일이 켜진 것처럼 보이면서
// 아무것도 막지 않는 상태가 고착된다.
func TestDegradedVerdictIsNotCached(t *testing.T) {
	restorePolicy(t)
	f := &flappy{failNext: 2}
	SetProvider(f)
	t.Cleanup(func() { SetProvider(MockProvider{}) })

	in := JudgeInput{Method: "POST", Path: "/p56/orders/{id}/cancel", ParamKeys: []string{"reason"}}

	// 1회차 — 장애. 가용성 위해 통과하되 degraded 로 표시된다.
	v1 := Judge(context.Background(), in)
	if !v1.Allow || !v1.Degraded {
		t.Fatalf("장애 1회차 = %+v, want allow=true degraded=true", v1)
	}

	// 2회차 — 여전히 장애. ★ 캐시 히트가 아니라 다시 물어봐야 한다.
	v2 := Judge(context.Background(), in)
	if !v2.Degraded {
		t.Errorf("장애 2회차 = %+v, want degraded", v2)
	}
	if f.count() != 2 {
		t.Errorf("프로바이더 호출 %d회, want 2 — 실패 판정이 캐시에서 재사용됐다", f.count())
	}
	ds := Decisions()
	if ds[len(ds)-1].Cached {
		t.Error("실패 판정이 캐시 히트로 기록됐다 — 재질의하지 않았다는 뜻")
	}

	// 3회차 — 프로바이더 복구. 같은 요청이 이제 차단돼야 한다.
	v3 := Judge(context.Background(), in)
	if v3.Allow {
		t.Error("프로바이더가 살아났는데도 통과했다 — 실패 판정이 고착됐다")
	}
	if v3.Degraded {
		t.Errorf("정상 판정인데 degraded 표시: %+v", v3)
	}

	// 4회차 — 정상 판정은 캐시된다(캐시 자체를 없앤 게 아니다).
	before := f.count()
	v4 := Judge(context.Background(), in)
	if v4.Allow || f.count() != before {
		t.Errorf("정상 판정이 캐시되지 않았다: allow=%v calls %d→%d", v4.Allow, before, f.count())
	}
	if last := Decisions(); !last[len(last)-1].Cached {
		t.Error("정상 판정 재질의가 캐시 히트로 기록되지 않았다")
	}
}

// 프로바이더 미설정·파싱 실패도 같은 취급이어야 한다.
func TestDegradedMarkedOnAllFailurePaths(t *testing.T) {
	restorePolicy(t)
	t.Cleanup(func() { SetProvider(MockProvider{}) })

	SetProvider(nil)
	if v := Judge(context.Background(), JudgeInput{Method: "POST", Path: "/p56/noprov"}); !v.Degraded || !v.Allow {
		t.Errorf("프로바이더 없음 = %+v, want allow+degraded", v)
	}

	garbage := &flappy{reply: "이건 JSON 이 아니다"}
	SetProvider(garbage)
	v := Judge(context.Background(), JudgeInput{Method: "POST", Path: "/p56/garbage"})
	if !v.Degraded || !v.Allow {
		t.Errorf("파싱 실패 = %+v, want allow+degraded", v)
	}
	if !strings.Contains(v.Reason, "파싱") {
		t.Errorf("이유에 원인이 안 남았다: %q", v.Reason)
	}
	// 파싱 실패도 캐시되면 안 된다 — 모델을 바꾸거나 프롬프트를 고쳐도 안 돌아온다.
	before := garbage.count()
	Judge(context.Background(), JudgeInput{Method: "POST", Path: "/p56/garbage"})
	if garbage.count() == before {
		t.Error("파싱 실패 판정이 캐시에서 재사용됐다")
	}
}

// fail-closed 정책 — 운영계는 "막지 못할 바엔 보내지 않는다" 를 고를 수 있어야 한다.
func TestFailClosedPolicy(t *testing.T) {
	restorePolicy(t)
	ResetHealth()
	t.Cleanup(func() { ResetHealth(); SetProvider(MockProvider{}) })

	down := &flappy{failNext: 100}
	SetProvider(down)
	in := JudgeInput{Method: "POST", Path: "/p56/policy", ParamKeys: []string{"amount"}}

	// 기본은 fail-open — 대상 가용성 우선(1원칙)
	if v := Judge(context.Background(), in); !v.Allow || !v.Degraded {
		t.Fatalf("기본 정책 = %+v, want allow+degraded", v)
	}
	if FailurePolicy() != FailOpen {
		t.Errorf("기본 정책 = %q, want %q", FailurePolicy(), FailOpen)
	}

	// fail-closed 로 전환하면 같은 장애가 차단이 된다
	if !SetFailurePolicy(FailClosed) {
		t.Fatal("SetFailurePolicy(block) 거부됨")
	}
	v := Judge(context.Background(), in)
	if v.Allow {
		t.Error("fail-closed 인데 통과시켰다")
	}
	if !v.Degraded {
		t.Error("차단해도 판단 불능이라는 사실은 남아야 한다")
	}
	if !strings.Contains(v.Reason, "판단 불능") {
		t.Errorf("이유에 원인이 안 남았다: %q", v.Reason)
	}

	// 오타는 무시하고 현재 정책을 유지한다 — 오타로 fail-closed 가 풀리면 안 된다
	if SetFailurePolicy("blcok") {
		t.Error("잘못된 값을 받아들였다")
	}
	if FailurePolicy() != FailClosed {
		t.Errorf("오타 후 정책 = %q, want block 유지", FailurePolicy())
	}
}

// 상태 전이에만 통지해야 한다 — 장애 중 매 요청을 감사에 쓰면 audit.json 이 터진다.
func TestDegradeNotifierFiresOnTransitionOnly(t *testing.T) {
	restorePolicy(t)
	ResetHealth()
	t.Cleanup(func() { ResetHealth(); SetProvider(MockProvider{}) })

	var mu sync.Mutex
	var events []bool
	SetDegradeNotifier(func(degraded bool, _ Health) {
		mu.Lock()
		events = append(events, degraded)
		mu.Unlock()
	})

	f := &flappy{failNext: 3}
	SetProvider(f)
	in := JudgeInput{Method: "POST", Path: "/p56/notify", ParamKeys: []string{"x"}}
	for i := 0; i < 3; i++ {
		Judge(context.Background(), in) // 장애 3회
	}
	Judge(context.Background(), in) // 복구
	Judge(context.Background(), in) // 정상(캐시)

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[0] != true || events[1] != false {
		t.Errorf("통지 = %v, want [true false] (진입 1회 + 복구 1회)", events)
	}
	if h := HealthSnapshot(); h.Degraded || h.Count != 3 {
		t.Errorf("health = %+v, want degraded=false count=3", h)
	}
}
