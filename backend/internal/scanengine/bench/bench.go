// Package bench — 스캔 품질 벤치마크 하네스 (이슈 #49).
//
// 목적: 정답셋으로 엔드포인트를 시드 → detector 실행 → 발견을 정답과 대조 → P/R/F1·오탐률 리포트.
// 정찰 벤치(#22)가 정찰에 해준 것을 스캔에 한다. detector 를 고치거나 추가할 때
// "좋아졌다 / 회귀 없다"를 숫자로 말하기 위한 계기판이다.
//
// ★ 설계 결정 (이슈 #49 착수 전 합의)
//
//  1. 측정 범위 = 스캔만 격리한다. 정답셋의 대상 목록으로 endpoints 트리를 직접 시드하고
//     크롤을 돌리지 않는다. 정찰을 앞에 끼우면 정찰이 못 찾은 경로가 스캔의 FN 으로 잡혀
//     detector 탓이 된다. 정찰 품질은 이미 recon/bench 가 따로 잰다.
//  2. 오탐(FP) = "정상 케이스에서 발동한 것"만 센다. 정답셋의 not_expect 에 적힌 조합이다.
//     정답셋에 없는 나머지 발견은 오탐이 아니라 미분류로 따로 집계한다 — 그래야 FP율이
//     정답셋 큐레이션 누락에 휘둘리지 않는다. 미분류 목록은 정답셋을 넓히라는 신호다.
//  3. 매칭 단위 = (대상 경로, VulnDef) 쌍. 도출리스트(FR-4.1)가 이 단위로 건수를 세므로
//     리포트 숫자와 일치한다. 같은 취약점이 파라미터 3개에서 잡혀도 1건이다.
//     detector 별 분해는 쌍이 아니라 발견 단위로 따로 낸다(어느 탐지기가 오탐을 만드는지).
//
// 경로 canonical 화는 정찰 벤치의 Canon 을 그대로 쓴다(중복 구현 방지).
package bench

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	reconbench "proxypoc/internal/recon/bench"
)

// GTTarget — 정답셋의 대상 1개.
//
// Expect 와 NotExpect 를 한 항목에 같이 둘 수 있다. vulnapp 의 /profile 이 그런 경우다 —
// 민감정보는 평문 노출(취약)이지만 접근통제는 정상이라 access-control 이 나오면 오탐이다.
type GTTarget struct {
	Path       string   `yaml:"path"`
	Methods    []string `yaml:"methods"`     // 비면 GET
	Params     []string `yaml:"params"`      // query 파라미터명
	BodyParams []string `yaml:"body_params"` // body 파라미터명
	Auth       bool     `yaml:"auth"`        // 정상 접근에 인증이 필요한가(접근통제 판정 힌트)
	Expect     []string `yaml:"expect"`      // 여기서 나와야 하는 VulnDef id — 정답(TP 후보)
	NotExpect  []string `yaml:"not_expect"`  // 여기서 나오면 오탐인 VulnDef id — FP 분모
	Note       string   `yaml:"note"`
}

// GroundTruth — 앱별 정답셋 (docs/scan-groundtruth/<app>.yaml).
type GroundTruth struct {
	App string `yaml:"app"`
	// Base — 외부 기동 대상의 주소. Handler 가 설정되면 무시된다.
	Base string `yaml:"base"`
	// Handler — 인프로세스로 띄울 내장 대상 이름(현재 "vulnlab"). 외부 기동이 필요 없다.
	Handler string `yaml:"handler"`
	// SiteWide — 앱 전체에 해당하는 취약점. 어느 경로에서 나와도 오탐이 아니고 정답도 아니다.
	// 예: vulnapp 은 보안 헤더를 일부러 안 붙이므로 sec-headers 가 모든 경로에서 나온다.
	SiteWide []string  `yaml:"site_wide"`
	Auth     *AuthConf `yaml:"auth"` // (선택) 기본 세션 주입. 인증 뒤 대상 점검용
	// Identities — 다중 신원 (FR-3.6). idor·privesc detector 는 신원이 2개 이상이어야 동작한다
	// (없으면 조용히 nil 을 반환해 접근통제 계열이 통째로 측정에서 빠진다).
	// 수직 권한상승까지 재려면 privileged 신원과 저권한 신원이 모두 있어야 한다.
	Identities []IdentityConf `yaml:"identities"`
	Targets    []GTTarget     `yaml:"targets"`
}

// AuthConf — 세션 주입 설정. 벤치 대상은 폐기용 테스트 앱이라 값을 YAML 에 둬도 무방(실 크리덴셜 금지).
type AuthConf struct {
	Cookies map[string]string `yaml:"cookies"`
	Headers map[string]string `yaml:"headers"`
}

// IdentityConf — 진단 신원 1개. name: anon 은 비인가 기준선으로 쓰인다(값 없이 이름만 둔다).
type IdentityConf struct {
	Name       string            `yaml:"name"`
	Cookies    map[string]string `yaml:"cookies"`
	Headers    map[string]string `yaml:"headers"`
	Privileged bool              `yaml:"privileged"` // 관리자 신원. 저권한과 대조해 수직 권한상승 판정
}

// LoadGroundTruth — YAML 정답셋 로드 + 검증.
func LoadGroundTruth(path string) (GroundTruth, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return GroundTruth{}, err
	}
	var gt GroundTruth
	if err := yaml.Unmarshal(b, &gt); err != nil {
		return GroundTruth{}, fmt.Errorf("%s: %w", path, err)
	}
	if len(gt.Targets) == 0 {
		return gt, fmt.Errorf("%s: targets 비어 있음", path)
	}
	if gt.Base == "" && gt.Handler == "" {
		return gt, fmt.Errorf("%s: base 또는 handler 중 하나는 있어야 한다", path)
	}
	// 같은 경로에 expect 와 not_expect 가 겹치면 채점이 모순된다 — 로드 시점에 잡는다.
	for _, t := range gt.Targets {
		for _, e := range t.Expect {
			for _, n := range t.NotExpect {
				if e == n {
					return gt, fmt.Errorf("%s: %s 의 %q 가 expect·not_expect 양쪽에 있다", path, t.Path, e)
				}
			}
		}
	}
	return gt, nil
}

// Found — 스캔이 낸 발견 1건. 쌍으로 접기 전의 원본 단위(detector 분해용).
//
// 증적(Evidence·Request·Response·RespCode·Severity)을 같이 나른다. 채점에는 안 쓰지만
// LLM 트리아지(FR-3.3)의 입력이다 — 판정은 "반사된 값이 실행 가능한 위치에 인코딩 없이
// 들어갔는가" 같은 응답 문맥으로 하므로, 증적을 버리면 모델에게 판단 재료를 주지 않고
// 판정을 요구하는 꼴이 되어 전부 uncertain 이 나온다.
type Found struct {
	Path     string
	Method   string
	Param    string
	VulnDef  string // 2층 VulnDef id. 비면 Detector id 로 폴백된다.
	Detector string
	Severity string
	Evidence string
	Request  string
	Response string
	RespCode int
	LLMFP    bool // LLM 이 오탐으로 판정 (FR-3.3)
}

// 발견 1건의 채점 분류.
const (
	ClassTP           = "TP"  // 정답(expect)과 일치
	ClassFP           = "FP"  // 정상 케이스(not_expect)에서 발동 — 확정 오탐
	ClassUnclassified = "미분류" // 정답셋에 언급이 없는 발견. 오탐으로 세지 않는다(합의 ②)
	ClassSiteWide     = "전역"  // site_wide 취약점 — 채점 제외
)

// DetectorStat — detector 별 분해. 발견 단위(쌍으로 접기 전).
type DetectorStat struct {
	Detector     string
	TP           int
	FP           int
	Unclassified int
}

// Metrics — 한 프로파일 실행의 채점 결과.
type Metrics struct {
	Profile string // seeded | seeded+llm

	GroundTruth  int // 정답 쌍 수 (expect 총합)
	Found        int // 발견 쌍 수 (site_wide 제외, 중복 제거)
	TP           int
	FP           int
	FN           int
	Unclassified int
	SiteWide     int // 전역 취약점 발견 쌍 수(참고)
	// Unreachable — 담당 detector 가 이번 실행에서 제외돼(파괴성 등) 애초에 잡힐 수 없던 정답 쌍.
	// FN 으로 세면 detector 를 억울하게 탓하게 되므로 GT 분모에서 빼고 따로 보고한다.
	Unreachable int

	Precision float64 // TP / (TP+FP) — 확정 판정 기준. 미분류는 분모에서 제외(합의 ②)
	Recall    float64 // TP / GroundTruth
	F1        float64
	FPRate    float64 // FP / (TP+FP). 구성상 1-Precision 과 같다(정찰 벤치와 표기 통일)

	Findings int // 원본 발견 건수(쌍으로 접기 전)
	Duration time.Duration

	MissedList       []string // 못 찾은 정답 쌍
	FPList           []string // 확정 오탐 쌍
	UnclassifiedList []string // 미분류 쌍 — 정답셋을 넓히라는 작업 목록
	UnreachableList  []string // 담당 detector 미실행으로 측정 불가한 정답 쌍

	ByDetector []DetectorStat
}

// LLMEffect — LLM 오탐 판정(FR-3.3)과 정답의 교차표.
//
// "오탐을 줄였는가"만 보면 절반만 본 것이다. 정탐까지 같이 지우면 오탐률은 좋아지고
// 도구는 나빠진다. 그래서 걸러낸 건수를 정답 기준으로 쪼개 HarmfulFP 를 같이 낸다.
type LLMEffect struct {
	Provider  string
	Flagged   int // LLM 이 false_positive 로 표시한 발견 수
	CorrectFP int // 그중 실제 오탐(not_expect) — 잘 걸러낸 것
	HarmfulFP int // 그중 실제 정탐(expect) — ★ 정탐을 지웠다
	OtherFP   int // 그중 미분류·전역
}

// LLMEffectOf — 판정이 붙은 발견 집합을 정답과 대조해 트리아지 효과를 낸다.
func LLMEffectOf(found []Found, gt GroundTruth) LLMEffect {
	expect, notExpect, siteWide := indexGT(gt, nil)
	var e LLMEffect
	e.Provider = "?"
	for _, f := range found {
		if !f.LLMFP {
			continue
		}
		e.Flagged++
		v := vulnOf(f)
		k := pairKey(f.Path, v)
		switch {
		case siteWide[v]:
			e.OtherFP++
		case expect[k]:
			e.HarmfulFP++
		case notExpect[k]:
			e.CorrectFP++
		default:
			e.OtherFP++
		}
	}
	return e
}

// Summary — 한 줄 요약.
func (e LLMEffect) Summary() string {
	if e.Flagged == 0 {
		return "LLM 이 오탐으로 표시한 발견 0건 — 트리아지가 아무것도 걸러내지 않았다"
	}
	s := fmt.Sprintf("LLM 이 %d건을 오탐으로 표시: 실제 오탐 %d · 미분류/전역 %d",
		e.Flagged, e.CorrectFP, e.OtherFP)
	if e.HarmfulFP > 0 {
		s += fmt.Sprintf(" · ★ 정탐 %d건을 지움(위험)", e.HarmfulFP)
	} else {
		s += " · 정탐 손실 0건"
	}
	return s
}

// indexGT — 정답셋을 채점용 색인으로. reachable 이 nil 이 아니면 도달 불가 정답은 expect 에서 뺀다.
func indexGT(gt GroundTruth, reachable map[string]bool) (expect, notExpect, siteWide map[string]bool) {
	expect, notExpect, siteWide = map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, v := range gt.SiteWide {
		siteWide[v] = true
	}
	for _, t := range gt.Targets {
		for _, v := range t.Expect {
			if reachable != nil && !reachable[v] {
				continue
			}
			expect[pairKey(t.Path, v)] = true
		}
		for _, v := range t.NotExpect {
			notExpect[pairKey(t.Path, v)] = true
		}
	}
	return expect, notExpect, siteWide
}

// pairKey — 채점 단위: "canon(path) vulnDef".
func pairKey(path, vuln string) string {
	return reconbench.Canon(path) + " " + vuln
}

// vulnOf — 발견의 취약점 식별자. VulnDef 가 비면 detector id 로 폴백한다
// (매핑이 없는 detector 도 채점에서 조용히 사라지지 않게).
func vulnOf(f Found) string {
	if f.VulnDef != "" {
		return f.VulnDef
	}
	return "detector:" + f.Detector
}

// Score — 발견 집합을 정답셋과 대조해 지표를 산출한다.
//
// reachable 이 nil 이 아니면, 거기 없는 VulnDef 를 기대하는 정답 쌍은 측정 불가로 빼고
// GT 분모에서도 제외한다. 담당 detector 가 파괴성이라 제외된 경우가 이에 해당한다 —
// 그런 쌍을 FN 으로 세면 detector 가 못 찾은 것처럼 보여 재현율이 거짓으로 낮아진다.
//
// skipLLMFP 가 true 면 LLM 이 오탐으로 판정한 발견을 제외하고 채점한다.
// 같은 발견 집합에 대해 false/true 로 두 번 부르면 "LLM 이 오탐을 실제로 줄이는가"가 나온다.
func Score(found []Found, gt GroundTruth, skipLLMFP bool, reachable map[string]bool) Metrics {
	siteWide := map[string]bool{}
	for _, v := range gt.SiteWide {
		siteWide[v] = true
	}
	// 정답·정상 케이스 색인. 키는 canonical 경로.
	expect := map[string]bool{}    // pairKey → 정답
	notExpect := map[string]bool{} // pairKey → 나오면 오탐
	var unreachable []string
	for _, t := range gt.Targets {
		for _, v := range t.Expect {
			if reachable != nil && !reachable[v] {
				unreachable = append(unreachable, pairKey(t.Path, v))
				continue
			}
			expect[pairKey(t.Path, v)] = true
		}
		for _, v := range t.NotExpect {
			notExpect[pairKey(t.Path, v)] = true
		}
	}

	seen := map[string]string{} // pairKey → 분류 (쌍 단위 중복 제거)
	byDet := map[string]*DetectorStat{}
	var findings int

	for _, f := range found {
		if skipLLMFP && f.LLMFP {
			continue
		}
		findings++
		v := vulnOf(f)
		k := pairKey(f.Path, v)

		var class string
		switch {
		case siteWide[v]:
			class = ClassSiteWide
		case expect[k]:
			class = ClassTP
		case notExpect[k]:
			class = ClassFP
		default:
			class = ClassUnclassified
		}
		seen[k] = class

		if class != ClassSiteWide { // 전역 취약점은 detector 분해에서도 뺀다(전 경로에서 나와 표를 덮는다)
			st := byDet[f.Detector]
			if st == nil {
				st = &DetectorStat{Detector: f.Detector}
				byDet[f.Detector] = st
			}
			switch class {
			case ClassTP:
				st.TP++
			case ClassFP:
				st.FP++
			default:
				st.Unclassified++
			}
		}
	}

	m := Metrics{GroundTruth: len(expect), Findings: findings,
		Unreachable: len(unreachable), UnreachableList: unreachable}
	for k, class := range seen {
		switch class {
		case ClassTP:
			m.TP++
		case ClassFP:
			m.FP++
			m.FPList = append(m.FPList, k)
		case ClassUnclassified:
			m.Unclassified++
			m.UnclassifiedList = append(m.UnclassifiedList, k)
		case ClassSiteWide:
			m.SiteWide++
		}
	}
	m.Found = m.TP + m.FP + m.Unclassified
	for k := range expect {
		if seen[k] != ClassTP {
			m.MissedList = append(m.MissedList, k)
		}
	}
	m.FN = len(m.MissedList)

	if d := m.TP + m.FP; d > 0 {
		m.Precision = float64(m.TP) / float64(d)
		m.FPRate = float64(m.FP) / float64(d)
	}
	if m.GroundTruth > 0 {
		m.Recall = float64(m.TP) / float64(m.GroundTruth)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}

	sort.Strings(m.MissedList)
	sort.Strings(m.FPList)
	sort.Strings(m.UnclassifiedList)
	sort.Strings(m.UnreachableList)
	for _, st := range byDet {
		m.ByDetector = append(m.ByDetector, *st)
	}
	sort.Slice(m.ByDetector, func(i, j int) bool { // 오탐 많은 순 → 조치 대상이 위로
		if m.ByDetector[i].FP != m.ByDetector[j].FP {
			return m.ByDetector[i].FP > m.ByDetector[j].FP
		}
		return m.ByDetector[i].Detector < m.ByDetector[j].Detector
	})
	return m
}

// TableHeader — Table() 컬럼 헤더.
func TableHeader() string {
	return fmt.Sprintf("%-12s %5s %6s %5s %5s %5s %7s   %6s %6s %6s  %6s %9s",
		"profile", "GT", "found", "TP", "FP", "FN", "미분류", "P", "R", "F1", "FPrate", "time")
}

// Table — 한 줄 요약(표 행).
func (m Metrics) Table() string {
	return fmt.Sprintf("%-12s %5d %6d %5d %5d %5d %7d   %5.1f%% %5.1f%% %5.1f%%  %5.1f%% %9s",
		m.Profile, m.GroundTruth, m.Found, m.TP, m.FP, m.FN, m.Unclassified,
		m.Precision*100, m.Recall*100, m.F1*100, m.FPRate*100, m.Duration.Round(time.Millisecond))
}

// Summary — 사람이 읽는 다줄 요약. 누락·오탐·미분류 목록과 detector 분해를 붙인다.
func (m Metrics) Summary(topN int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] P=%.1f%% R=%.1f%% F1=%.1f%% FP율=%.1f%%  (GT=%d found=%d TP=%d FP=%d FN=%d 미분류=%d 전역=%d)  발견 %d건  %s\n",
		m.Profile, m.Precision*100, m.Recall*100, m.F1*100, m.FPRate*100,
		m.GroundTruth, m.Found, m.TP, m.FP, m.FN, m.Unclassified, m.SiteWide, m.Findings,
		m.Duration.Round(time.Millisecond))
	if len(m.MissedList) > 0 {
		fmt.Fprintf(&b, "  누락(FN) %d: %s\n", len(m.MissedList), head(m.MissedList, topN))
	}
	if len(m.FPList) > 0 {
		fmt.Fprintf(&b, "  오탐(FP) %d: %s\n", len(m.FPList), head(m.FPList, topN))
	}
	if len(m.UnclassifiedList) > 0 {
		fmt.Fprintf(&b, "  미분류 %d (정답셋 확장 후보): %s\n", len(m.UnclassifiedList), head(m.UnclassifiedList, topN))
	}
	if len(m.UnreachableList) > 0 {
		fmt.Fprintf(&b, "  측정불가 %d (담당 detector 미실행 — GT 분모에서 제외): %s\n",
			len(m.UnreachableList), head(m.UnreachableList, topN))
	}
	if len(m.ByDetector) > 0 {
		fmt.Fprintf(&b, "  detector 분해 (오탐 많은 순):\n")
		for _, st := range m.ByDetector {
			fmt.Fprintf(&b, "    %-16s TP=%-3d FP=%-3d 미분류=%d\n", st.Detector, st.TP, st.FP, st.Unclassified)
		}
	}
	return b.String()
}

func head(ss []string, n int) string {
	if n <= 0 || n >= len(ss) {
		return strings.Join(ss, ", ")
	}
	return strings.Join(ss[:n], ", ") + fmt.Sprintf(", …(+%d)", len(ss)-n)
}
