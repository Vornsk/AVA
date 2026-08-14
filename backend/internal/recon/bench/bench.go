package bench

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// GTEndpoint — ground-truth 한 항목.
type GTEndpoint struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

// GroundTruth — 앱별 정답셋 (docs/recon-groundtruth/<app>.yaml).
type GroundTruth struct {
	App       string       `yaml:"app"`
	Base      string       `yaml:"base"`
	Auth      *Auth        `yaml:"auth"` // (선택) 인증 크롤 설정 (#31). 없으면 비인증.
	Endpoints []GTEndpoint `yaml:"endpoints"`
}

// Auth — 인증 크롤 설정 (#31). 정적 쿠키/헤더(1차) 또는 로그인 시퀀스(2차).
// 벤치 대상은 폐기용 훈련 앱이라 test 크리덴셜을 YAML 에 둬도 무방(실 크리덴셜 금지).
type Auth struct {
	Cookies map[string]string `yaml:"cookies"`
	Headers map[string]string `yaml:"headers"`
	Login   *AuthLogin        `yaml:"login"`
}

// AuthLogin — 로그인 시퀀스(제품 auth.LoginSeq 재사용). CSRF 토큰 사전취득 지원.
type AuthLogin struct {
	URL        string            `yaml:"url"`
	Method     string            `yaml:"method"` // 기본 POST
	Fields     map[string]string `yaml:"fields"`
	TokenURL   string            `yaml:"token_url"`   // (선택) CSRF 토큰 페이지
	TokenField string            `yaml:"token_field"` // 예: user_token
	TokenParam string            `yaml:"token_param"` // 폼 파라미터명(기본 token_field)
	LoggedOut  string            `yaml:"logged_out"`  // 세션 만료 판단 정규식
}

// LoadGroundTruth — YAML 정답셋 로드.
func LoadGroundTruth(path string) (GroundTruth, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return GroundTruth{}, err
	}
	var gt GroundTruth
	if err := yaml.Unmarshal(b, &gt); err != nil {
		return GroundTruth{}, fmt.Errorf("%s: %w", path, err)
	}
	if len(gt.Endpoints) == 0 {
		return gt, fmt.Errorf("%s: endpoints 비어 있음", path)
	}
	return gt, nil
}

// Endpoint — 정찰이 발견한 엔드포인트(구체 경로).
type Endpoint struct {
	Method string
	Path   string
}

// Metrics — 한 프로파일 실행의 채점 결과.
type Metrics struct {
	Profile string // static | headless | passive

	GroundTruth int // 정답 수(canonical)
	Discovered  int // 발견 수(canonical, 중복 제거)
	Matched     int // 정답과 일치(TP)
	Extra       int // 정답에 없는 발견(FP)
	Missed      int // 못 찾은 정답(FN)

	Precision float64
	Recall    float64
	F1        float64
	FPRate    float64 // 오탐율 = Extra / Discovered

	Inflation float64 // 트리 팽창률 = 제품 정규화 distinct / 하네스 canonical distinct (≥1, 높을수록 미접힘)

	Pages    int           // 가져온 페이지(≈요청수)
	Duration time.Duration // 소요시간

	MissedList []string // 못 찾은 정답 키(정렬)
	ExtraList  []string // 오탐 키(정렬)
}

// Score — 발견 집합을 ground-truth 와 대조해 지표를 산출한다.
//
//	rawCount : 제품이 구분한 (method,path) 수(팽창률 분자). Discovered 는 하네스 canonical 로 중복 제거.
func Score(discovered []Endpoint, rawCount int, gt GroundTruth) Metrics {
	gtSet := map[string]bool{}
	for _, e := range gt.Endpoints {
		gtSet[key(e.Method, e.Path)] = true
	}
	discSet := map[string]bool{}
	for _, e := range discovered {
		discSet[key(e.Method, e.Path)] = true
	}

	var matched int
	var extraList []string
	for k := range discSet {
		if gtSet[k] {
			matched++
		} else {
			extraList = append(extraList, k)
		}
	}
	var missedList []string
	for k := range gtSet {
		if !discSet[k] {
			missedList = append(missedList, k)
		}
	}
	sort.Strings(extraList)
	sort.Strings(missedList)

	m := Metrics{
		GroundTruth: len(gtSet),
		Discovered:  len(discSet),
		Matched:     matched,
		Extra:       len(extraList),
		Missed:      len(missedList),
		MissedList:  missedList,
		ExtraList:   extraList,
	}
	if m.Discovered > 0 {
		m.Precision = float64(matched) / float64(m.Discovered)
		m.FPRate = float64(m.Extra) / float64(m.Discovered)
		m.Inflation = float64(rawCount) / float64(m.Discovered)
	}
	if m.GroundTruth > 0 {
		m.Recall = float64(matched) / float64(m.GroundTruth)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	return m
}

// Table — 한 줄 요약(표 행). 헤더는 TableHeader.
func (m Metrics) Table() string {
	return fmt.Sprintf("%-9s %5d %6d %5d %5d %5d   %5.1f%% %5.1f%% %5.1f%%  %5.1f%%  %5.2fx %5d %8s",
		m.Profile, m.GroundTruth, m.Discovered, m.Matched, m.Extra, m.Missed,
		m.Precision*100, m.Recall*100, m.F1*100, m.FPRate*100, m.Inflation, m.Pages,
		m.Duration.Round(time.Millisecond))
}

// TableHeader — Table() 컬럼 헤더.
func TableHeader() string {
	return fmt.Sprintf("%-9s %5s %6s %5s %5s %5s   %6s %6s %6s  %6s  %6s %5s %8s",
		"profile", "GT", "disc", "TP", "FP", "FN", "P", "R", "F1", "FPrate", "infl", "pages", "time")
}

// Summary — 사람이 읽는 다줄 요약(누락/오탐 상위 포함).
func (m Metrics) Summary(topN int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] P=%.1f%% R=%.1f%% F1=%.1f%%  (GT=%d disc=%d TP=%d FP=%d FN=%d)  팽창률=%.2fx  pages=%d  %s\n",
		m.Profile, m.Precision*100, m.Recall*100, m.F1*100,
		m.GroundTruth, m.Discovered, m.Matched, m.Extra, m.Missed, m.Inflation, m.Pages, m.Duration.Round(time.Millisecond))
	if len(m.MissedList) > 0 {
		fmt.Fprintf(&b, "  누락(FN) %d: %s\n", len(m.MissedList), head(m.MissedList, topN))
	}
	if len(m.ExtraList) > 0 {
		fmt.Fprintf(&b, "  오탐(FP) %d: %s\n", len(m.ExtraList), head(m.ExtraList, topN))
	}
	return b.String()
}

func head(ss []string, n int) string {
	if n <= 0 || n >= len(ss) {
		return strings.Join(ss, ", ")
	}
	return strings.Join(ss[:n], ", ") + fmt.Sprintf(", …(+%d)", len(ss)-n)
}
