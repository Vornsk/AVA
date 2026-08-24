package llm

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// recorder — 받은 system 프롬프트를 기록하고, 그 내용에 따라 다른 verdict 를 돌려주는 스텁.
// 프롬프트가 실제로 갈아끼워지는지 + 캐시가 정책별로 갈라지는지 확인하는 데 쓴다.
type recorder struct {
	mu      sync.Mutex
	systems []string
}

func (r *recorder) Name() string { return "recorder" }

func (r *recorder) Complete(_ context.Context, system, _ string) (string, error) {
	r.mu.Lock()
	r.systems = append(r.systems, system)
	r.mu.Unlock()
	if strings.Contains(system, "Default to BLOCK when uncertain") {
		return `{"allow":false,"reason":"strict","confidence":0.9}`, nil
	}
	return `{"allow":true,"reason":"loose","confidence":0.5}`, nil
}

func (r *recorder) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.systems)
}

// 테스트 사이에 전역 정책 상태가 새지 않게 복원.
func restorePolicy(t *testing.T) {
	t.Helper()
	b, a := BasePolicy(), JudgePolicy()
	t.Cleanup(func() { SetBasePolicy(b); SetJudgePolicy(a) })
}

// 미설정(balanced) 프롬프트가 이슈 #53 이전 anthropic.go 의 sysPrompt 상수와 바이트 단위로
// 같아야 한다. 하위호환의 핵심 — 설정을 안 건드린 사용자는 판단 결과가 달라지면 안 된다.
//
// 이 상수는 main 의 e317d97 "판단 프롬프트에 허용 기준 명시" 로 교정된 문구다(10케이스 실측
// qwen2.5:3b 4/10 → 9/10). 프리셋으로 옮기면서 이 교정이 되돌아가면 커버리지가 통째로 사라진다.
func TestBalancedPresetIsLegacyPrompt(t *testing.T) {
	const legacy = `You are a gatekeeper in an AUTHORIZED vulnerability assessment. The scan is permitted; your ONLY job is to stop requests that would cause IRREVERSIBLE harm to the target system.

BLOCK (allow=false) only if forwarding could cause an effect that cannot be undone:
  destroying or overwriting data (delete, purge, restore, reset, wipe)
  cancelling/finalising a transaction (order cancel, payment, refund, transfer)
  disabling access (deactivate, suspend, revoke, logout)
  emitting something external that cannot be recalled (send mail/SMS, publish, notify)

ALLOW (allow=true) everything else, including ordinary state changes:
  reads and searches, even via POST
  creating or updating records that can simply be edited back (profile, settings, cart, inventory quantity, draft)
  generating reports or exports

Default to ALLOW when uncertain: this is an authorized test, and over-blocking silently removes coverage. The hint field only tells you WHY the rule engine deferred; it is NOT evidence of risk.

Examples:
  POST /api/search q,page          -> {"allow":true,"reason":"read-only search","confidence":0.9}
  PUT /api/users/{id}/profile nickname -> {"allow":true,"reason":"reversible field update","confidence":0.9}
  POST /api/orders/{id}/cancel reason  -> {"allow":false,"reason":"order cancellation is irreversible","confidence":0.9}

Reply with ONLY compact JSON in English: {"allow":boolean,"reason":string,"confidence":number between 0 and 1}.`

	pol, ok := presetPolicy(PresetBalanced)
	if !ok {
		t.Fatal("balanced 프리셋 없음")
	}
	if pol.System != legacy {
		t.Errorf("balanced 프롬프트가 기존 상수와 다름:\n got: %q\nwant: %q", pol.System, legacy)
	}
}

// 세 프리셋 모두 같은 골격(BLOCK 기준·ALLOW 기준·기본 방향·예시)을 지켜야 한다.
// 기준 없이 쓰면 모델이 상태변경을 전부 차단해 커버리지가 사라진다(e317d97 실측).
func TestPresetsKeepCalibratedShape(t *testing.T) {
	for _, id := range Presets() {
		pol, _ := presetPolicy(id)
		for _, must := range []string{"BLOCK (allow=false)", "ALLOW (allow=true)", "Examples:", "POST /api/search"} {
			if !strings.Contains(pol.System, must) {
				t.Errorf("%s 프리셋에 %q 없음 — 기준 없는 프롬프트는 전건 차단으로 무너진다", id, must)
			}
		}
		if !strings.Contains(pol.System, "Default to ALLOW when uncertain") &&
			!strings.Contains(pol.System, "Default to BLOCK when uncertain") {
			t.Errorf("%s 프리셋에 불확실할 때의 기본 방향이 없음", id)
		}
	}
}

func TestResolvePolicy(t *testing.T) {
	restorePolicy(t)
	SetBasePolicy(mustPreset(PresetBalanced))

	// 미설정 → 기본 정책
	if pol, err := ResolvePolicy("", ""); err != nil || pol.ID != PresetBalanced {
		t.Errorf("미설정 → %+v, err=%v; want balanced", pol, err)
	}
	// 대소문자·공백 관용
	if pol, err := ResolvePolicy("  STRICT ", ""); err != nil || pol.ID != PresetStrict {
		t.Errorf("' STRICT ' → %+v, err=%v; want strict", pol, err)
	}
	// 알 수 없는 프리셋 → 기본 정책 폴백 + error
	pol, err := ResolvePolicy("paranoid", "")
	if err == nil {
		t.Error("알 수 없는 프리셋인데 error 없음")
	}
	if pol.ID != PresetBalanced {
		t.Errorf("폴백 = %q, want balanced", pol.ID)
	}
	// 기본 정책이 strict 면 미설정도 strict 로 폴백해야 한다 (조용한 완화 금지)
	SetBasePolicy(mustPreset(PresetStrict))
	if pol, _ := ResolvePolicy("", ""); pol.ID != PresetStrict {
		t.Errorf("base=strict 인데 미설정 → %q", pol.ID)
	}
	if pol, err := ResolvePolicy("nope", ""); err == nil || pol.ID != PresetStrict {
		t.Errorf("base=strict 인데 잘못된 프리셋 → %q, err=%v", pol.ID, err)
	}
}

func TestResolvePolicyCustom(t *testing.T) {
	restorePolicy(t)
	SetBasePolicy(mustPreset(PresetBalanced))

	pol, err := ResolvePolicy("strict", "Block every request to /internal.")
	if err != nil {
		t.Fatalf("custom err = %v", err)
	}
	if pol.ID != "custom" {
		t.Errorf("id = %q, want custom (custom 이 preset 보다 우선)", pol.ID)
	}
	if !strings.Contains(pol.System, "Block every request to /internal.") {
		t.Error("사용자 문구가 빠짐")
	}
	if !strings.Contains(pol.System, verdictContract) {
		t.Error("출력 계약이 자동 부착되지 않음 — 파싱 실패 시 전건 fail-open 이 된다")
	}
	// 이미 계약을 포함한 커스텀은 중복 부착하지 않는다
	twice, _ := ResolvePolicy("", "Do it. "+verdictContract)
	if strings.Count(twice.System, verdictContract) != 1 {
		t.Errorf("출력 계약 중복 부착: %q", twice.System)
	}
	// 서로 다른 커스텀은 지문이 달라야 한다 (캐시 분리의 근거)
	other, _ := ResolvePolicy("", "Block every request to /admin.")
	if other.Hash == pol.Hash {
		t.Error("다른 커스텀 프롬프트인데 해시가 같다")
	}
	// 길이 상한 초과 → 거절 + 기본 정책
	long, err := ResolvePolicy("", strings.Repeat("가", MaxCustomLen+1))
	if err == nil {
		t.Error("길이 초과인데 error 없음")
	}
	if long.ID != PresetBalanced {
		t.Errorf("길이 초과 폴백 = %q, want balanced", long.ID)
	}
}

func TestPresetsAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, id := range Presets() {
		pol, ok := presetPolicy(id)
		if !ok {
			t.Fatalf("%s 프리셋 없음", id)
		}
		if prev, dup := seen[pol.Hash]; dup {
			t.Errorf("%s 와 %s 의 해시가 같다 — 캐시가 분리되지 않는다", id, prev)
		}
		seen[pol.Hash] = id
		if !strings.Contains(pol.System, verdictContract) {
			t.Errorf("%s 에 출력 계약 없음", id)
		}
	}
	if len(Presets()) != 3 {
		t.Errorf("프리셋 %d개, want 3 (strict/balanced/permissive)", len(Presets()))
	}
}

// 이 이슈의 핵심 회귀 테스트 — 같은 요청이라도 정책이 다르면 캐시를 공유하면 안 된다.
// 공유하면 프로젝트 A(permissive)의 allow 가 프로젝트 B(strict)로 새어 들어간다.
func TestJudgeCacheIsolatedByPolicy(t *testing.T) {
	restorePolicy(t)
	rec := &recorder{}
	SetProvider(rec)
	t.Cleanup(func() { SetProvider(MockProvider{}) })

	in := JudgeInput{Method: "POST", Path: "/p53/transfer", ParamKeys: []string{"amount"}}

	SetJudgePolicy(mustPreset(PresetPermissive))
	loose := Judge(context.Background(), in)
	if !loose.Allow {
		t.Fatalf("permissive verdict = %+v, want allow", loose)
	}
	if loose.Prompt != PresetPermissive || loose.PromptHash == "" {
		t.Errorf("verdict 에 프롬프트 식별자 없음: %+v", loose)
	}

	SetJudgePolicy(mustPreset(PresetStrict))
	tight := Judge(context.Background(), in)
	if tight.Allow {
		t.Error("정책을 strict 로 바꿨는데 permissive 판단이 캐시에서 재사용됐다 (캐시 오염)")
	}
	if tight.Prompt != PresetStrict {
		t.Errorf("verdict.prompt = %q, want strict", tight.Prompt)
	}
	if rec.calls() != 2 {
		t.Errorf("프로바이더 호출 %d회, want 2 (정책마다 1회)", rec.calls())
	}

	// 같은 정책으로 다시 물으면 캐시 적중 — 호출은 늘지 않아야 한다.
	again := Judge(context.Background(), in)
	if rec.calls() != 2 {
		t.Errorf("같은 정책 재질의에 프로바이더 호출 %d회, want 2", rec.calls())
	}
	if again.Prompt != PresetStrict || again.PromptHash != tight.PromptHash {
		t.Errorf("캐시된 verdict 에 프롬프트 식별자가 유실됨: %+v", again)
	}
	ds := Decisions()
	if last := ds[len(ds)-1]; !last.Cached {
		t.Error("세 번째 판단은 캐시 적중이어야 한다")
	}
}

// 활성 프로바이더가 실제로 정책 프롬프트를 받는지 (프롬프트가 갈아끼워지는지) 확인.
func TestJudgeSendsPolicySystemPrompt(t *testing.T) {
	restorePolicy(t)
	rec := &recorder{}
	SetProvider(rec)
	t.Cleanup(func() { SetProvider(MockProvider{}) })

	pol, err := ResolvePolicy("", "Never forward anything to /vault.")
	if err != nil {
		t.Fatal(err)
	}
	SetJudgePolicy(pol)
	Judge(context.Background(), JudgeInput{Method: "GET", Path: "/p53/vault"})

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.systems) != 1 {
		t.Fatalf("호출 %d회", len(rec.systems))
	}
	if rec.systems[0] != pol.System {
		t.Errorf("프로바이더가 받은 system = %q, want %q", rec.systems[0], pol.System)
	}
}

// ApplyProject — 프로젝트 값이 비면 기본 정책, 있으면 그 정책.
func TestApplyProject(t *testing.T) {
	restorePolicy(t)
	SetBasePolicy(mustPreset(PresetStrict))

	if pol, err := ApplyProject("", ""); err != nil || pol.ID != PresetStrict {
		t.Errorf("빈 프로젝트 설정 → %q, err=%v; want strict(기본)", pol.ID, err)
	}
	if pol, err := ApplyProject(PresetPermissive, ""); err != nil || pol.ID != PresetPermissive {
		t.Errorf("permissive → %q, err=%v", pol.ID, err)
	}
	if JudgePolicy().ID != PresetPermissive {
		t.Errorf("활성 정책이 전환되지 않음: %q", JudgePolicy().ID)
	}
	// 잘못된 값이면 기본 정책으로 되돌아가고 error 를 알린다 (조용한 정책 완화 금지)
	pol, err := ApplyProject("bogus", "")
	if err == nil || pol.ID != PresetStrict || JudgePolicy().ID != PresetStrict {
		t.Errorf("잘못된 값 폴백 실패: pol=%q active=%q err=%v", pol.ID, JudgePolicy().ID, err)
	}
}

// mock 프로바이더가 커스텀 판단 프롬프트를 다른 작업으로 오라우팅하지 않아야 한다.
// (커스텀 문구에 "triage" 같은 단어가 섞일 수 있다)
func TestMockRoutesJudgeByContract(t *testing.T) {
	restorePolicy(t)
	SetProvider(MockProvider{})
	pol, err := ResolvePolicy("", "You are a triage gatekeeper. Block financial endpoints.")
	if err != nil {
		t.Fatal(err)
	}
	SetJudgePolicy(pol)
	v := Judge(context.Background(), JudgeInput{Method: "POST", Path: "/p53/mockroute", ParamKeys: []string{"amount"}})
	if v.Reason == "" || v.Prompt != "custom" {
		t.Errorf("verdict = %+v", v)
	}
	if v.Allow {
		t.Error("금융성 파라미터인데 허용 — mock 이 판단이 아닌 다른 작업으로 라우팅됐을 수 있다")
	}
}
