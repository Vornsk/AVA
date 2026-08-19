// Package parammine — 정찰 파라미터 마이닝 (이슈 #40).
//
// endpoints 트리는 관측된 요청에 나타난 파라미터만 담는다. 서버가 처리하지만 UI·트래픽에
// 드러나지 않는 hidden 파라미터(debug 플래그, 권한 우회 필드, 레거시 필드)는 실제 인젝션·
// 접근통제 진입점인데 지금까지의 정찰로는 영영 못 찾는다.
//
// ★ 기본 비활성(옵트인). 능동 주입은 소음·법적 경계가 있어 안전장치가 전제다(호출자 게이트).
//
//	· 옵트인 — 호출자가 켜야만 요청이 나간다 (crawler.Options.ParamMine)
//	· GET only·비파괴 — 쿼리스트링으로만 주입한다(이슈 착수 합의 ①)
//	· 스코프 하드 게이트(FR-2.1) · 크롤러와 같은 레이트리밋 — probe.Client 재사용
//	· 요청 예산 상한 — 넘으면 중단하고 그 사실을 리포트에 남긴다
//	· 감사 기록 — 누가 언제 켰는지는 호출자가 audit.Record
//
// 판정은 세 신호를 합친다(합의 ②): 이름/값 반사, 기준 대비 길이·상태 변화, 그리고 같은
// 파라미터에 다른 값 2개를 넣은 두 값 차등. 세 신호 모두 soft-404 캘리브레이션(#26/#27)과
// 같은 정신 — "기준과 다른 반응"만 실재로 본다 — 이라 정적 반사 오탐을 걸러낸다.
//
// 효율은 벌크 이분탐색(합의 ④): 파라미터를 뭉텅이로 주입해 반응이 없으면 그 뭉치를 통째로
// 버리고, 반응한 뭉치만 절반씩 나눠 범인을 좁힌다. 하나씩 주입하는 것보다 요청이 훨씬 적다.
package parammine

import (
	"bufio"
	"context"
	_ "embed"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/recon/probe"
)

//go:embed wordlist.txt
var wordlistRaw string

const (
	// DefaultBudget — 기본 요청 예산. 벌크 이분탐색이라 엔드포인트당 요청이 적다.
	DefaultBudget = 600
	// MaxBudget — 요청 예산 상한. 클라이언트가 준 예산을 이 값으로 캡한다 — 능동 주입이라
	// 무제한 예산은 자기·대상 DoS 증폭기가 된다(스코프 게이트가 있어도 요청 폭주는 남는다).
	MaxBudget = 20000
	// bucketSize — 한 번에 주입할 파라미터 수. URL 길이·서버 한도를 고려한 상한.
	bucketSize = 32
	// maxEndpoints — 마이닝할 엔드포인트 수 상한(예산·소음 방지).
	maxEndpoints = 50
	// maxPerEndpoint — 한 엔드포인트에서 등록할 파라미터 상한(반사-투성이 엔드포인트 방어).
	maxPerEndpoint = 30
)

// Report — 파라미터 마이닝 1회 결과.
type Report struct {
	Words     int      `json:"words"`     // 워드리스트 항목 수
	Endpoints int      `json:"endpoints"` // 실제로 마이닝한 엔드포인트 수
	Probed    int      `json:"probed"`    // 보낸 요청 수
	Found     int      `json:"found"`     // 발견해 등록한 hidden 파라미터 수
	Errors    int      `json:"errors"`
	Budget    int      `json:"budget"`
	Exhausted bool     `json:"exhausted"` // 예산 소진으로 중단했는가
	FoundList []string `json:"found_list,omitempty"`
	Duration  string   `json:"duration"`
}

// Words — embed 된 워드리스트(주석·빈 줄 제외, 중복 제거, 순서 유지).
func Words() []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(wordlistRaw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out
}

// Run — 트리의 검증된 GET 엔드포인트에 워드리스트를 주입해 hidden 파라미터를 찾는다.
// budget 이 0 이하면 DefaultBudget. 발견분은 tree.AddMinedParam 으로 붙는다(출처는 mined 플래그).
func Run(ctx context.Context, tree *endpoints.Tree, client *http.Client, budget int) Report {
	start := time.Now()
	if budget <= 0 {
		budget = DefaultBudget
	}
	if budget > MaxBudget {
		budget = MaxBudget // 무제한 능동 주입 방지 (자기·대상 DoS 증폭 차단)
	}
	base := Words()
	rep := Report{Words: len(base), Budget: budget}

	m := &miner{p: probe.New(ctx, client), ctx: ctx, tree: tree, budget: budget, rep: &rep}
	for _, t := range tree.Targets() {
		if ctx.Err() != nil || m.over() {
			break
		}
		if rep.Endpoints >= maxEndpoints || !hasGET(t) || t.Path == "" {
			continue
		}
		if m.mineEndpoint(t, base) {
			rep.Endpoints++
		}
	}

	rep.Exhausted = m.hitBudget
	rep.Probed, rep.Errors = m.p.Probes, m.p.Errors
	rep.Duration = time.Since(start).String()
	log.Printf("[PMINE] wordlist=%d 엔드포인트=%d 프로브=%d 발견=%d 예산=%d%s (%s)",
		rep.Words, rep.Endpoints, rep.Probed, rep.Found, rep.Budget, exhaustedMark(rep.Exhausted), rep.Duration)
	for _, f := range rep.FoundList {
		log.Printf("[PMINE]   + %s", f)
	}
	return rep
}

type miner struct {
	p         *probe.Client
	ctx       context.Context
	tree      *endpoints.Tree
	budget    int
	rep       *Report
	seq       int
	hitBudget bool // 예산 상한에 걸려 멈춘 적이 있는가
}

// baseCtx — 한 엔드포인트의 기준 반응. 무의미 파라미터를 넣었을 때의 상태·크기·자연 요동과,
// 이 엔드포인트가 파라미터 이름/값을 반사하는지(반사-투성이면 그 신호는 노이즈).
type baseCtx struct {
	status      int
	size        int64
	band        int64  // 서로 다른 무의미 파라미터 간 크기 차 = 자연 요동
	body        string // 기준 응답 본문 — 이름 반사는 "기준엔 없는데 주입 후 나타남"으로 판정
	nameReflect bool   // 무의미 파라미터 이름이 응답에 그대로 나오는가(반사-투성이 방어)
	valReflect  bool   // 무의미 파라미터 값이 응답에 그대로 나오는가
}

// echoed — name 이 주입 응답 body 에는 있고 기준 body 에는 없는가(우연한 부분문자열 배제).
func (c baseCtx) echoed(body, name string) bool {
	return !c.nameReflect && strings.Contains(body, name) && !strings.Contains(c.body, name)
}

// mineEndpoint — 한 엔드포인트를 마이닝한다. 실제로 프로브했으면 true.
func (m *miner) mineEndpoint(t endpoints.Target, words []string) bool {
	base := url.URL{Scheme: t.Scheme, Host: t.Host, Path: t.Path}
	if base.Scheme == "" {
		base.Scheme = "https"
	}
	// 이미 관측된 파라미터는 마이닝에서 뺀다.
	have := map[string]bool{}
	for _, p := range t.Params {
		have[p.Name] = true
	}
	cand := make([]string, 0, len(words))
	for _, w := range words {
		if !have[w] {
			cand = append(cand, w)
		}
	}
	if len(cand) == 0 {
		return false
	}

	// 기준: 무의미 파라미터를 넣은 두 번의 대조 요청.
	cn1, cv1 := m.tok(), m.tok()
	s1, b1, ok := m.get(base, cn1, cv1)
	if !ok {
		return false
	}
	cn2, cv2 := m.tok(), m.tok()
	s2, b2, ok := m.get(base, cn2, cv2)
	if !ok {
		return false
	}
	ctx := baseCtx{
		status:      s1.Status,
		size:        s1.Size,
		band:        absI64(s1.Size - s2.Size),
		body:        b1,
		nameReflect: strings.Contains(b1, cn1) || strings.Contains(b2, cn2),
		valReflect:  strings.Contains(b1, cv1) || strings.Contains(b2, cv2),
	}

	found := 0
	for i := 0; i < len(cand) && found < maxPerEndpoint; i += bucketSize {
		end := i + bucketSize
		if end > len(cand) {
			end = len(cand)
		}
		m.search(base, cand[i:end], ctx, t, &found)
	}
	return true
}

// search — 뭉치를 테스트해 반응이 없으면 통째로 버리고, 있으면 절반씩 좁힌다(벌크 이분탐색).
func (m *miner) search(base url.URL, names []string, ctx baseCtx, t endpoints.Target, found *int) {
	if len(names) == 0 || *found >= maxPerEndpoint || m.stop() {
		return
	}
	if !m.testBucket(base, names, ctx) {
		return
	}
	if len(names) == 1 {
		if m.confirm(base, names[0], ctx) {
			if m.tree.AddMinedParam(t.Host, t.Path, names[0], "query", "string") {
				*found++
				m.rep.Found++
				if len(m.rep.FoundList) < 50 {
					m.rep.FoundList = append(m.rep.FoundList, t.Host+t.Path+"?"+names[0])
				}
			}
		}
		return
	}
	mid := len(names) / 2
	m.search(base, names[:mid], ctx, t, found)
	m.search(base, names[mid:], ctx, t, found)
}

// testBucket — 뭉치를 한 번에 주입해 기준과 다른 반응이 있는가.
func (m *miner) testBucket(base url.URL, names []string, ctx baseCtx) bool {
	if m.stop() {
		return false
	}
	q := base.Query()
	toks := make([]string, len(names))
	for i, n := range names {
		toks[i] = m.tok()
		q.Set(n, toks[i])
	}
	base.RawQuery = q.Encode()
	sig, body, ok := m.p.ProbeURL(&base)
	if !ok {
		return false
	}
	if sig.Status != ctx.status || m.sizeChanged(ctx, sig.Size) {
		return true
	}
	for _, n := range names {
		if ctx.echoed(body, n) {
			return true // 서버가 파라미터 이름을 되비춘다(기준엔 없던 것)
		}
	}
	if !ctx.valReflect {
		for _, tk := range toks {
			if strings.Contains(body, tk) {
				return true
			}
		}
	}
	return false
}

// confirm — 단일 파라미터를 두 값 차등으로 확정한다. 정적 반사·soft-404 오탐을 거른다.
func (m *miner) confirm(base url.URL, name string, ctx baseCtx) bool {
	if m.stop() {
		return false
	}
	va, vb := m.tok(), m.tok()
	sa, ba, ok := m.get(base, name, va)
	if !ok {
		return false
	}
	sb, bb, ok := m.get(base, name, vb)
	if !ok {
		return false
	}
	tol := m.tol(ctx)
	da, db := sa.Size-ctx.size, sb.Size-ctx.size // 기준(무의미 파라미터) 대비 크기 변화
	switch {
	case sa.Status != ctx.status || sb.Status != ctx.status:
		return true // 이 파라미터가 상태를 바꾼다
	case ctx.echoed(ba, name) || ctx.echoed(bb, name):
		return true // 서버가 파라미터 이름을 되비춘다 = 인식한다
	case !ctx.valReflect && strings.Contains(ba, va) && strings.Contains(bb, vb):
		return true // 값이 응답에 따라 들어온다(두 값 모두) = 처리한다
	case da > tol && db > tol, da < -tol && db < -tol:
		return true // 존재만으로 응답 크기가 기준과 일관되게 다르다(값 무관·1회 요동 아님)
	case absI64(sa.Size-sb.Size) > tol:
		return true // 다른 값이 응답 길이를 다르게 만든다 = 값에 반응한다
	}
	return false
}

// get — 파라미터 하나를 넣어 GET. probe.Client 가 스코프·인증·레이트리밋·요청수 계상을 한다.
func (m *miner) get(base url.URL, name, val string) (probe.Sig, string, bool) {
	q := base.Query()
	q.Set(name, val)
	base.RawQuery = q.Encode()
	return m.p.ProbeURL(&base)
}

// tok — 반사 탐지용 토큰. 끝에 'x' 경계를 붙여 "avamn1" 이 "avamn10" 의 부분문자열로
// 오탐되지 않게 한다(strings.Contains 는 경계를 모른다).
func (m *miner) tok() string { m.seq++; return "avamn" + strconv.Itoa(m.seq) + "x" }

// stop — 더 프로브하면 안 되는가(컨텍스트 취소 또는 예산 소진). 취소는 즉시 멈춰야 한다.
func (m *miner) stop() bool { return m.ctx.Err() != nil || m.over() }

func (m *miner) over() bool {
	if m.p.Probes >= m.budget {
		m.hitBudget = true
		return true
	}
	return false
}
func (m *miner) tol(c baseCtx) int64 {
	t := c.size * 2 / 100 // 기준 크기의 2%
	if t < 8 {
		t = 8
	}
	return c.band + t
}
func (m *miner) sizeChanged(c baseCtx, sz int64) bool { return absI64(sz-c.size) > m.tol(c) }

func hasGET(t endpoints.Target) bool {
	for _, meth := range t.Methods {
		if meth == "GET" {
			return true
		}
	}
	return false
}

func absI64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func exhaustedMark(b bool) string {
	if b {
		return "(소진)"
	}
	return ""
}
