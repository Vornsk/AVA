// 판단 프롬프트 정책 (이슈 #53) — 판단(Judge) system 프롬프트를 프로젝트별로 고른다.
//
// 왜 필요한가: 같은 엔진이라도 대상마다 요구되는 보수성이 다르다. 운영 결제계는
// 거래성 요청을 최대한 막아야 하고, 폐기 예정 스테이징은 공격적으로 훑는 편이 낫다.
// 지금까지 프롬프트는 상수 하나였다.
//
// ★ 캐시 정합성 — 이 변경의 숨은 위험:
//
//	프롬프트가 상수가 아니게 된 순간, "요청 시그니처"만으로 만든 캐시 키는 서로 다른
//	정책의 판단을 섞는다. 프로젝트 A(permissive)에서 allow 로 캐시된 항목이 프로젝트
//	B(strict)로 전환한 뒤 그대로 재사용된다 — 같은 프로세스, 같은 전역 캐시이므로.
//	그래서 Policy.Hash 를 캐시 키에 넣는다(sig 참조). 정책이 다르면 키가 다르고,
//	정책이 바뀌면 옛 항목은 자연히 미스가 된다(별도 무효화 없음. 캐시는 프로세스 메모리다).
package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// 프리셋 ID — 심각도(보수성) 단일 축. 대상 유형(결제·스테이징)은 프롬프트가 아니라
// 이미 있는 scope·rules 로 표현한다.
const (
	PresetStrict     = "strict"     // 운영계: 애매하면 차단
	PresetBalanced   = "balanced"   // 기본값. 기존 하드코딩 프롬프트와 동일 (하위호환)
	PresetPermissive = "permissive" // 폐기 가능 스테이징: 애매하면 허용
)

// MaxCustomLen — 커스텀 프롬프트 최대 길이(문자). 토큰 폭증·프롬프트 주입 표면 억제.
const MaxCustomLen = 4000

// verdictContract — 모든 판단 프롬프트가 반드시 지켜야 하는 출력 계약.
// 커스텀 프롬프트에도 자동 부착한다. 이 계약이 깨지면 파싱 실패 → 전건 기본 허용(fail-open)이
// 되어 판단 스테이지가 조용히 무력화된다.
const verdictContract = `Reply with ONLY compact JSON: {"allow":boolean,"reason":string,"confidence":number}.`

// presetBody — 프리셋별 역할·기준 서술. 뒤에 verdictContract 가 붙는다.
// "gatekeeper" 단어는 mock 프로바이더의 작업 구분에 쓰인다(mock.go).
var presetBody = map[string]string{
	PresetBalanced: "You are a security proxy gatekeeper for an authorized vulnerability assessment. " +
		"Given a token-minimized HTTP request descriptor (no bodies/values), decide whether forwarding it " +
		"is safe for the TARGET's availability (avoid destructive/irreversible actions).",

	PresetStrict: "You are a security proxy gatekeeper for an authorized vulnerability assessment of a PRODUCTION system " +
		"that must not be disturbed. Given a token-minimized HTTP request descriptor (no bodies/values), decide whether " +
		"forwarding it is safe for the TARGET's availability and data integrity. " +
		"Block anything that could move money, alter or delete records, or trigger an irreversible side effect — " +
		"payment, transfer, refund, order, subscription, delete, purge, reset, deploy, or outbound mail/notification. " +
		"Treat an unfamiliar state-changing endpoint as unsafe. When in doubt, block.",

	PresetPermissive: "You are a security proxy gatekeeper for an authorized vulnerability assessment of a disposable " +
		"staging/test environment. Given a token-minimized HTTP request descriptor (no bodies/values), decide whether " +
		"forwarding it is safe. The target is expendable and broad coverage matters more than caution, so allow by default. " +
		"Block only clearly catastrophic, system-wide and irreversible operations — bulk deletion or purge of all data, " +
		"account/tenant teardown, infrastructure shutdown. When in doubt, allow.",
}

// Policy — 활성 판단 프롬프트 정책.
type Policy struct {
	ID     string `json:"id"`     // strict | balanced | permissive | custom
	Hash   string `json:"hash"`   // System 의 sha256 앞 8자리 — 캐시 키 구성요소이자 감사 식별자
	System string `json:"system"` // 실제 system 프롬프트 (출력 계약 포함)
}

// String — 감사·로그용 식별자. 예: "strict(4f2a1c9d)".
func (p Policy) String() string { return p.ID + "(" + p.Hash + ")" }

func newPolicy(id, system string) Policy {
	sum := sha256.Sum256([]byte(system))
	return Policy{ID: id, Hash: hex.EncodeToString(sum[:])[:8], System: system}
}

func presetPolicy(id string) (Policy, bool) {
	body, ok := presetBody[id]
	if !ok {
		return Policy{}, false
	}
	return newPolicy(id, body+" "+verdictContract), true
}

// Presets — 사용 가능한 프리셋 ID (정렬).
func Presets() []string {
	out := make([]string, 0, len(presetBody))
	for id := range presetBody {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ErrCustomTooLong — 커스텀 프롬프트가 MaxCustomLen 초과.
var ErrCustomTooLong = errors.New("커스텀 판단 프롬프트가 너무 김")

// ResolvePolicy — 설정값(preset, custom)을 정책으로 해석한다.
//
//	custom 이 비지 않으면 커스텀 — 출력 계약을 자동 부착하고 ID 는 "custom".
//	custom 이 비면 preset. preset 도 비면 기본 정책(BasePolicy) — 미설정 시 하위호환.
//	알 수 없는 preset·과길이 custom 이면 기본 정책으로 폴백하고 error 를 함께 반환한다
//	(호출자가 경고를 남기되 판단 스테이지는 계속 돈다).
func ResolvePolicy(preset, custom string) (Policy, error) {
	if c := strings.TrimSpace(custom); c != "" {
		if len([]rune(c)) > MaxCustomLen {
			return BasePolicy(), fmt.Errorf("%w: %d자 > %d자", ErrCustomTooLong, len([]rune(c)), MaxCustomLen)
		}
		if !strings.Contains(c, verdictContract) {
			c += " " + verdictContract // 출력 계약 강제 — 파싱 실패로 인한 fail-open 방지
		}
		return newPolicy("custom", c), nil
	}
	switch p := strings.ToLower(strings.TrimSpace(preset)); p {
	case "":
		return BasePolicy(), nil
	default:
		if pol, ok := presetPolicy(p); ok {
			return pol, nil
		}
		return BasePolicy(), fmt.Errorf("알 수 없는 판단 프롬프트 프리셋 %q (사용 가능: %s)", preset, strings.Join(Presets(), ", "))
	}
}

var (
	pmu    sync.Mutex
	base   = mustPreset(PresetBalanced) // 기동 시 project.config.yaml 로 정해지는 기본 정책
	active = mustPreset(PresetBalanced) // 현재 적용 중인 정책 (프로젝트 전환·런타임 변경으로 바뀜)
)

func mustPreset(id string) Policy {
	p, ok := presetPolicy(id)
	if !ok {
		panic("llm: 알 수 없는 기본 프리셋 " + id)
	}
	return p
}

// SetBasePolicy — 기본 정책 지정 (기동 시 project.config.yaml 기준).
// 프로젝트가 자기 정책을 지정하지 않았을 때 되돌아갈 자리다. 활성 정책도 함께 맞춘다.
func SetBasePolicy(p Policy) {
	pmu.Lock()
	base, active = p, p
	pmu.Unlock()
}

// BasePolicy — 기본 정책.
func BasePolicy() Policy {
	pmu.Lock()
	defer pmu.Unlock()
	return base
}

// SetJudgePolicy — 활성 정책 지정 (프로젝트 전환·런타임 변경).
func SetJudgePolicy(p Policy) {
	pmu.Lock()
	active = p
	pmu.Unlock()
}

// ApplyProject — 프로젝트 설정값으로 활성 정책을 전환한다 (기동·프로젝트 활성화 공용).
// 값이 비었으면 기본 정책, 잘못됐으면 기본 정책으로 폴백하고 error 를 함께 돌려준다.
func ApplyProject(preset, custom string) (Policy, error) {
	pol, err := ResolvePolicy(preset, custom)
	SetJudgePolicy(pol)
	return pol, err
}

// JudgePolicy — 현재 활성 정책.
func JudgePolicy() Policy {
	pmu.Lock()
	defer pmu.Unlock()
	return active
}
