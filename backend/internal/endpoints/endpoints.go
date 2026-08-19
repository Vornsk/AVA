// Package endpoints — 공격면(엔드포인트) 트리 (FR-2.4, §3 Endpoint/Parameter 모델).
// URL 경로 기반 트리로 누적하고, 노드마다 method·파라미터·인증필요여부·위험판단결과·경로를 담는다.
//
//	· 경로 정규화: /user/42, /user/43 → /user/{id} (dedup, FR-2.3)
//	· 파라미터: 위치(query/body/cookie) + 타입추정 + 필수여부 + 샘플값(마스킹). 원문 값은 안 남김
//	· 결과를 endpoints.json 에 트리로 실시간 저장
package endpoints

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxypoc/internal/masking"
)

// nowRFC3339 — 캡처 시각(UTC, 초 단위). 발견 시각 기록용 (이슈 #7).
func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// Param — 파라미터 (§3 Parameter). 원문 값 대신 마스킹 샘플만 저장.
type Param struct {
	Name     string `json:"name"`
	In       string `json:"in"`                 // query | body | cookie
	Type     string `json:"type,omitempty"`     // int | bool | uuid | email | string
	Sample   string `json:"sample,omitempty"`   // 마스킹된 샘플값
	Required bool   `json:"required,omitempty"` // 해당 엔드포인트의 모든 요청에 등장했는가
	Mined    bool   `json:"mined,omitempty"`    // 파라미터 마이닝으로 발견 — 관측이 아님 (이슈 #40)
}

type paramAgg struct {
	ins    map[string]bool
	typ    string
	sample string
	seen   int  // 이 파라미터가 등장한 요청 수
	mined  bool // 파라미터 마이닝(#40)이 발견 — 트래픽 관측이 아님
}

type node struct {
	segment    string
	path       string
	lastPath   string // 마지막으로 본 concrete 경로 (스캔 재요청용)
	scheme     string // http | https (스캔 재요청 시 원 스킴 보존)
	methods    map[string]bool
	params     map[string]*paramAgg
	count      int
	auth       bool
	verdict    string
	firstSeen  string   // 최초 캡처 시각 (RFC3339, FR-2.4 조회 강화 — 이슈 #7)
	lastSeen   string   // 최근 캡처 시각 (RFC3339)
	source     string   // 출처 신뢰도 등급 (SrcSpec … SrcStaticRegex) — 이슈 #25·#26
	unverified bool     // 라이브니스 프로브에서 실재가 확인되지 않음 — 삭제 대신 강등 (이슈 #26)
	authOnly   bool     // 인증 뒤에만 나타난 표면 (비인증 크롤엔 없던 것) — 접근통제 진단 후보 (이슈 #38)
	labels     []string // 의미 라벨(auth·payment·pii 등) — LLM/룰 분류 (이슈 #41)
	varChild   string   // 이 자리의 변수 자식 세그먼트 ("{slug}" 또는 명세 플레이스홀더 "{username}")
	varSpec    bool     // varChild 가 명세 선언인가 (true 면 값 모양과 무관하게 흡수) — 이슈 #25
	children   map[string]*node
}

func newNode(seg, path string) *node {
	return &node{
		segment:  seg,
		path:     path,
		methods:  map[string]bool{},
		params:   map[string]*paramAgg{},
		children: map[string]*node{},
	}
}

// Tree — 한 테넌트(프로젝트)의 엔드포인트 트리 (멀티테넌시 §5.1). name 이 있으면 파일로 덤프.
type Tree struct {
	mu    sync.Mutex
	roots map[string]*node
	name  string // 덤프 파일명 ("" = 인메모리, 파일 안 씀)
}

// NewTree — 테넌트용 인메모리 트리(파일 덤프 없음).
func NewTree() *Tree { return &Tree{roots: map[string]*node{}} }

// def — 기본(전역) 트리. 경로 분류 규칙(정규식)은 normalize.go 에 모여 있다(이슈 #24).
var def = &Tree{roots: map[string]*node{}, name: "endpoints.json"}

// Default — 기본(전역) 트리.
func Default() *Tree { return def }

// Reset — 전역 트리를 빈 상태로 초기화. 벤치 하네스의 프로파일별 격리 측정용(#22).
// (운영 경로에서는 사용하지 않는다 — 테스트/툴링 전용.)
func Reset() {
	def.mu.Lock()
	defer def.mu.Unlock()
	def.roots = map[string]*node{}
}

// ── 전역 위임 함수 (하위호환, :8080 공유 프록시) ──
func Record(scheme, host, method, rawPath string, params []Param, auth bool, verdict string) {
	def.Record(scheme, host, method, rawPath, params, auth, verdict)
}

// RecordSpec — 명세(OpenAPI/GraphQL/sitemap)에서 얻은 엔드포인트를 출처 "spec" 으로 기록 (이슈 #25).
func RecordSpec(scheme, host, method, rawPath string, params []Param, auth bool, verdict string) {
	def.RecordSpec(scheme, host, method, rawPath, params, auth, verdict)
}

// RecordFrom — 출처 등급을 지정해 기록 (이슈 #26). 크롤러가 기록 지점별로 등급을 고른다.
func RecordFrom(source, scheme, host, method, rawPath string, params []Param, auth bool, verdict string) {
	def.RecordFrom(source, scheme, host, method, rawPath, params, auth, verdict)
}
func Snapshot() []OutNode                    { return def.Snapshot() }
func Find(host, path string) (OutNode, bool) { return def.Find(host, path) }
func Targets() []Target                      { return def.Targets() }
func TargetsAll() []Target                   { return def.TargetsAll() }
func Summary() SummaryData                   { return def.Summary() }

// Names — Param 목록에서 이름만 (LLM 입력용 키, 중복 제거·정렬).
func Names(ps []Param) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		if !seen[p.Name] {
			seen[p.Name] = true
			out = append(out, p.Name)
		}
	}
	sort.Strings(out)
	return out
}

// ExtractParams — 쿼리·쿠키·form 본문에서 파라미터(위치·타입·샘플) 추출. 본문은 복원.
// 주입 전 원본 파라미터를 잡으려면 auth.Inject 이전에 호출할 것.
func ExtractParams(req *http.Request) []Param {
	var ps []Param
	seen := map[string]bool{}
	add := func(name, in, value string) {
		k := in + ":" + name
		if seen[k] {
			return
		}
		seen[k] = true
		ps = append(ps, Param{
			Name:   name,
			In:     in,
			Type:   inferType(value),
			Sample: masking.Sample(name, value),
		})
	}

	for k, vs := range req.URL.Query() {
		add(k, "query", first(vs))
	}
	for _, c := range req.Cookies() {
		add(c.Name, "cookie", c.Value)
	}
	ct := req.Header.Get("Content-Type")
	if req.Body != nil && strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		body, err := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body)) // 본문 복원
		if err == nil {
			if vals, e := url.ParseQuery(string(body)); e == nil {
				for k, vs := range vals {
					add(k, "body", first(vs))
				}
			}
		}
	}
	// multipart/form-data: 파일 필드는 In="file"(필드명)로, 일반 필드는 body 로 기록.
	if req.Body != nil && strings.HasPrefix(ct, "multipart/form-data") {
		body, err := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body)) // 본문 복원(별도 리더로 파싱)
		if err == nil {
			if _, mp, e := mime.ParseMediaType(ct); e == nil && mp["boundary"] != "" {
				mr := multipart.NewReader(bytes.NewReader(body), mp["boundary"])
				if form, e := mr.ReadForm(1 << 20); e == nil {
					for name, vs := range form.Value {
						add(name, "body", first(vs))
					}
					for name, files := range form.File {
						fname := ""
						if len(files) > 0 {
							fname = files[0].Filename
						}
						add(name, "file", fname) // 업로드 지점 표식
					}
					_ = form.RemoveAll()
				}
			}
		}
	}

	// application/json: 중첩 스칼라 leaf 를 dot-path(예: user.id, items.0.name)로 In="json" 기록.
	if req.Body != nil && strings.HasPrefix(ct, "application/json") {
		body, err := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body)) // 본문 복원
		if err == nil {
			var v any
			if json.Unmarshal(body, &v) == nil {
				flattenJSON("", v, 0, func(path, val string) { add(path, "json", val) })
			}
		}
	}

	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Name != ps[j].Name {
			return ps[i].Name < ps[j].Name
		}
		return ps[i].In < ps[j].In
	})
	return ps
}

// flattenJSON — JSON 값을 재귀 순회하며 스칼라 leaf 를 dot-path 로 add(path,val) 호출.
// 객체는 키, 배열은 인덱스로 경로를 잇는다(예: user.id, items.0.name). 폭주 방지로 깊이 8 제한.
func flattenJSON(prefix string, v any, depth int, add func(path, val string)) {
	if depth > 8 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flattenJSON(p, sub, depth+1, add)
		}
	case []any:
		for i, sub := range t {
			p := strconv.Itoa(i)
			if prefix != "" {
				p = prefix + "." + strconv.Itoa(i)
			}
			flattenJSON(p, sub, depth+1, add)
		}
	default:
		if s, ok := scalarString(v); ok && prefix != "" {
			add(prefix, s)
		}
	}
}

// scalarString — JSON 스칼라 값(문자열/숫자/불리언)을 문자열로. 중첩 객체·배열·null 은 (,false).
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	}
	return "", false
}

// Record — 요청 1건을 트리에 반영하고(필요 시) 파일 갱신. host 는 authority(host[:port]).
func (t *Tree) Record(scheme, host, method, rawPath string, params []Param, auth bool, verdict string) {
	t.record(scheme, host, method, rawPath, params, auth, verdict, "")
}

// RecordSpec — 명세에서 얻은 엔드포인트 기록 (이슈 #25).
// 경로에 {name} 플레이스홀더가 있으면 그 자리를 "변수 자리"로 선언한다 — 이후 크롤이 같은 자리에
// 구체값(/users/v1/alice)을 기록하면 별도 노드를 만들지 않고 이 노드로 흡수된다.
func (t *Tree) RecordSpec(scheme, host, method, rawPath string, params []Param, auth bool, verdict string) {
	t.record(scheme, host, method, rawPath, params, auth, verdict, srcSpec)
}

// RecordFrom — 출처 등급을 지정해 기록 (이슈 #26).
func (t *Tree) RecordFrom(source, scheme, host, method, rawPath string, params []Param, auth bool, verdict string) {
	t.record(scheme, host, method, rawPath, params, auth, verdict, source)
}

func (t *Tree) record(scheme, host, method, rawPath string, params []Param, auth bool, verdict, source string) {
	if scheme == "" {
		scheme = "https"
	}
	norm := NormalizePath(rawPath)

	t.mu.Lock()
	root, ok := t.roots[host]
	if !ok {
		root = newNode(host, "")
		t.roots[host] = root
	}
	cur, parent := root, (*node)(nil)
	acc := ""
	for _, s := range splitSegs(norm) {
		acc += "/" + s
		if seg, redirected := absorb(cur, s, source); redirected {
			s = seg
			acc = cur.path + "/" + s
		}
		ch, ok := cur.children[s]
		if !ok {
			ch = newNode(s, acc)
			ch.source = source // 새 노드는 발견한 출처를 그대로 (이슈 #26)
			cur.children[s] = ch
		} else if sourceRank(source) > sourceRank(ch.source) {
			ch.source = source // 기존 노드는 더 믿을 만한 출처로만 승격
		}
		if !NeedsProbe(source) {
			ch.unverified = false // 프로브 면제 등급으로 다시 잡혔다 = 실재한다
		}
		if source == srcSpec && isTemplate(s) {
			declareVar(cur, s) // 명세가 "이 자리는 변수"라고 알려준다 (이슈 #25)
		}
		parent, cur = cur, ch
	}
	cur.methods[method] = true
	cur.lastPath = rawPath
	cur.scheme = scheme
	cur.count++
	cur.auth = cur.auth || auth
	if verdict != "" {
		cur.verdict = verdict
	}
	now := nowRFC3339()
	if cur.firstSeen == "" {
		cur.firstSeen = now
	}
	cur.lastSeen = now

	// 파라미터 집계 (위치 합집합, 타입·샘플 유지, 요청당 1회 seen 증가)
	namesThisReq := map[string]bool{}
	for _, p := range params {
		agg := cur.params[p.Name]
		if agg == nil {
			agg = &paramAgg{ins: map[string]bool{}}
			cur.params[p.Name] = agg
		}
		agg.ins[p.In] = true
		if agg.typ == "" {
			agg.typ = p.Type
		}
		if agg.sample == "" {
			agg.sample = p.Sample
		}
		namesThisReq[p.Name] = true
	}
	for name := range namesThisReq {
		cur.params[name].seen++
	}
	// 형제 다양성 클러스터링 — 방금 삽입한 자리의 형제가 값처럼 보이면 {slug} 로 접는다(이슈 #24).
	// 파라미터 집계 뒤에 호출해야 "파라미터 있는 노드는 보존" 조건이 제대로 걸린다.
	if parent != nil {
		foldSiblings(parent, parent == root)
	}
	t.mu.Unlock()

	log.Printf("[EP  ] %s %s  methods=%v params=%d auth=%v", host, norm, method, len(params), auth)
	t.dump()
}

// OutNode — 트리 출력(JSON·MCP·파일).
type OutNode struct {
	Segment    string    `json:"segment"`
	Path       string    `json:"path,omitempty"`
	Methods    []string  `json:"methods,omitempty"`
	Params     []Param   `json:"params,omitempty"`
	Count      int       `json:"count,omitempty"`
	Auth       bool      `json:"auth_required,omitempty"`
	Verdict    string    `json:"verdict,omitempty"`
	FirstSeen  string    `json:"first_seen,omitempty"` // 최초 캡처 시각 (이슈 #7)
	LastSeen   string    `json:"last_seen,omitempty"`  // 최근 캡처 시각
	Source     string    `json:"source,omitempty"`     // 출처 신뢰도 등급 (이슈 #25·#26)
	Unverified bool      `json:"unverified,omitempty"` // 라이브니스 프로브 미통과 (이슈 #26)
	AuthOnly   bool      `json:"auth_only,omitempty"`  // 인증 뒤에만 보이는 표면 (이슈 #38)
	Labels     []string  `json:"labels,omitempty"`     // 의미 라벨 (이슈 #41)
	Children   []OutNode `json:"children,omitempty"`
}

func toOut(n *node) OutNode {
	o := OutNode{
		Segment:    n.segment,
		Path:       n.path,
		Methods:    sortedKeys(n.methods),
		Params:     outParams(n),
		Count:      n.count,
		Auth:       n.auth,
		Verdict:    n.verdict,
		FirstSeen:  n.firstSeen,
		LastSeen:   n.lastSeen,
		Source:     n.source,
		Unverified: n.unverified,
		AuthOnly:   n.authOnly,
		Labels:     n.labels,
	}
	keys := make([]string, 0, len(n.children))
	for k := range n.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		o.Children = append(o.Children, toOut(n.children[k]))
	}
	return o
}

// Snapshot — 호스트별 엔드포인트 트리.
func (t *Tree) Snapshot() []OutNode {
	t.mu.Lock()
	defer t.mu.Unlock()
	hosts := make([]string, 0, len(t.roots))
	for h := range t.roots {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	out := make([]OutNode, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, toOut(t.roots[h]))
	}
	return out
}

// Find — host + 정규화 path 로 노드 조회 (자식 제외).
func (t *Tree) Find(host, path string) (OutNode, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur := t.lookup(host, path) // Record 의 흡수와 같은 규칙으로 하강 (이슈 #24·#25)
	if cur == nil {
		return OutNode{}, false
	}
	o := toOut(cur)
	o.Children = nil
	return o, true
}

// Target — 스캔 대상 엔드포인트 (concrete 경로 포함).
type Target struct {
	Scheme     string   `json:"scheme,omitempty"` // http | https (스캔 재요청용)
	Host       string   `json:"host"`             // authority (host[:port])
	Path       string   `json:"path"`             // concrete (재요청 가능)
	Methods    []string `json:"methods,omitempty"`
	Params     []Param  `json:"params,omitempty"`
	Auth       bool     `json:"auth_required"`        // 정상 접근 시 인증을 동반했는가 (접근통제 판정 힌트)
	Verdict    string   `json:"verdict,omitempty"`    // 위험 판단 결과 (§5.2; 자동 대상선정 힌트, FR-3.9)
	Count      int      `json:"count,omitempty"`      // 누적 히트 수 (조회 강화 — 이슈 #7)
	FirstSeen  string   `json:"first_seen,omitempty"` // 최초 캡처 시각 (RFC3339)
	LastSeen   string   `json:"last_seen,omitempty"`  // 최근 캡처 시각 (RFC3339)
	Source     string   `json:"source,omitempty"`     // 출처 신뢰도 등급 (이슈 #25·#26)
	Unverified bool     `json:"unverified,omitempty"` // 라이브니스 프로브 미통과 (이슈 #26)
	AuthOnly   bool     `json:"auth_only,omitempty"`  // 인증 뒤에만 보이는 표면 (이슈 #38)
	Labels     []string `json:"labels,omitempty"`     // 의미 라벨 (이슈 #41)
}

// Interesting — 공격면이 넓은 대상인가 (파라미터/인증/위험판단 존재). FR-3.9 자동선정용.
func (t Target) Interesting() bool {
	return len(t.Params) > 0 || t.Auth || t.Verdict != ""
}

// Targets — 스캔 대상 목록 (메서드가 있는 실제 엔드포인트만).
// Targets — 스캔 대상 목록. 라이브니스 프로브에서 실재가 확인되지 않은 노드(unverified)는
// 기본 제외한다 (이슈 #26). 강등이지 삭제가 아니므로 트리에는 남아 있고 TargetsAll 로 볼 수 있다.
func (t *Tree) Targets() []Target { return t.targets(false) }

// TargetsAll — unverified 를 포함한 전체 대상 (이슈 #26 진단·감사용).
func (t *Tree) TargetsAll() []Target { return t.targets(true) }

func (t *Tree) targets(includeUnverified bool) []Target {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Target
	var walk func(host string, n *node)
	walk = func(host string, n *node) {
		if len(n.methods) > 0 && n.lastPath != "" && (includeUnverified || !n.unverified) {
			out = append(out, Target{
				Scheme:     n.scheme,
				Host:       host,
				Path:       n.lastPath,
				Methods:    sortedKeys(n.methods),
				Params:     outParams(n),
				Auth:       n.auth,
				Verdict:    n.verdict,
				Count:      n.count,
				FirstSeen:  n.firstSeen,
				LastSeen:   n.lastSeen,
				Source:     n.source,
				Unverified: n.unverified,
				AuthOnly:   n.authOnly,
				Labels:     n.labels,
			})
		}
		for _, c := range n.children {
			walk(host, c)
		}
	}
	for host, r := range t.roots {
		walk(host, r)
	}
	return out
}

// MarkUnverified — 라이브니스 프로브에서 실재가 확인되지 않은 노드를 강등한다 (이슈 #26).
// 지우지 않는다 — 삭제하면 왜 제외됐는지 근거가 사라져 재현할 수 없다.
// path 는 구체 경로여도 되고(정규화·흡수 규칙으로 하강한다) 템플릿이어도 된다.
func (t *Tree) MarkUnverified(host, path string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.lookup(host, NormalizePath(path))
	if n == nil {
		return false
	}
	n.unverified = true
	return true
}

// MarkUnverified — 기본(전역) 트리에 위임.
func MarkUnverified(host, path string) bool { return def.MarkUnverified(host, path) }

// MarkAuthOnly — 인증 뒤에만 나타난 노드를 접근통제 진단 후보로 표시한다 (이슈 #38).
// 인증 델타 크롤이 "비인증엔 없고 인증엔 있는" 경로에 붙인다. path 는 구체·템플릿 무관.
func (t *Tree) MarkAuthOnly(host, path string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.lookup(host, NormalizePath(path))
	if n == nil {
		return false
	}
	n.authOnly = true
	return true
}

// MarkAuthOnly — 기본(전역) 트리에 위임.
func MarkAuthOnly(host, path string) bool { return def.MarkAuthOnly(host, path) }

// AddMinedParam — 파라미터 마이닝(#40)이 발견한 hidden 파라미터를 노드에 붙인다.
// 관측이 아니므로 seen 을 올리지 않고(Required=false) mined 로 표시한다. 노드가 없으면 false.
// In 이 "" 면 query 로 본다. detector.injectable 이 query 를 자동으로 스캔 대상에 포함한다.
func (t *Tree) AddMinedParam(host, path, name, in, typ string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.lookup(host, NormalizePath(path))
	if n == nil {
		return false
	}
	if in == "" {
		in = "query"
	}
	agg, ok := n.params[name]
	if !ok {
		agg = &paramAgg{ins: map[string]bool{}}
		n.params[name] = agg
	}
	agg.ins[in] = true
	if agg.typ == "" {
		agg.typ = typ
	}
	agg.mined = true
	return true
}

// AddMinedParam — 기본(전역) 트리에 위임.
func AddMinedParam(host, path, name, in, typ string) bool {
	return def.AddMinedParam(host, path, name, in, typ)
}

// SetLabels — 엔드포인트에 의미 라벨을 설정한다 (이슈 #41). 노드가 없으면 false.
// 라벨은 노드 단위이고 출처·파라미터와 직교한다. 규제 매핑(E5)·커버리지(E6)가 읽는다.
// 인메모리 설정만 한다(Mark* 와 동일) — 파일 영속화는 호출자가 일괄 Persist 로 한 번만 한다
// (엔드포인트마다 전체 트리를 덤프하면 O(n) 파일 쓰기가 된다).
func (t *Tree) SetLabels(host, path string, labels []string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.lookup(host, NormalizePath(path))
	if n == nil {
		return false
	}
	n.labels = append(n.labels[:0:0], labels...) // 방어 복사(호출자 슬라이스 공유 방지)
	return true
}

// SetLabels — 기본(전역) 트리에 위임.
func SetLabels(host, path string, labels []string) bool { return def.SetLabels(host, path, labels) }

// Persist — 현재 트리를 저장 파일에 한 번 덤프한다(인메모리 트리는 무시).
// 라벨링(#41)처럼 여러 노드를 인메모리로 갱신한 뒤 마지막에 한 번만 영속화할 때 쓴다.
func (t *Tree) Persist() { t.dump() }

// Persist — 기본(전역) 트리에 위임.
func Persist() { def.dump() }

// lookup — host+정규화 경로로 노드를 찾는다(호출자가 t.mu 보유). 없으면 nil.
func (t *Tree) lookup(host, path string) *node {
	cur, ok := t.roots[host]
	if !ok {
		return nil
	}
	for _, s := range splitSegs(path) {
		ch, ok := cur.children[s]
		if !ok {
			if seg, redirected := absorb(cur, s, ""); redirected {
				ch, ok = cur.children[seg]
			}
		}
		if !ok {
			return nil
		}
		cur = ch
	}
	return cur
}

// outParams — 노드의 파라미터를 []Param 로 (toOut과 공유 로직).
func outParams(n *node) []Param {
	names := make([]string, 0, len(n.params))
	for name := range n.params {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Param, 0, len(names))
	for _, name := range names {
		agg := n.params[name]
		out = append(out, Param{
			Name:     name,
			In:       strings.Join(sortedKeys(agg.ins), ","),
			Type:     agg.typ,
			Sample:   agg.sample,
			Required: agg.seen == n.count && !agg.mined, // 마이닝분은 관측이 아니라 Required 판정 제외
			Mined:    agg.mined,
		})
	}
	return out
}

// SummaryData — 요약 통계.
type SummaryData struct {
	Endpoints int `json:"endpoints"`
	Hosts     int `json:"hosts"`
	Hits      int `json:"total_hits"`
}

// Summary — 실제 엔드포인트(메서드 있는 노드) 수·호스트 수·총 히트.
func (t *Tree) Summary() SummaryData {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := SummaryData{Hosts: len(t.roots)}
	var walk func(n *node)
	walk = func(n *node) {
		if len(n.methods) > 0 {
			s.Endpoints++
			s.Hits += n.count
		}
		for _, c := range n.children {
			walk(c)
		}
	}
	for _, r := range t.roots {
		walk(r)
	}
	return s
}

// ── 영속화 (왕복 저장/복원) ────────────────────────────────────────
// 표시용 OutNode 와 달리 lastPath·scheme·집계 원본(seen)까지 보존해 재시작 후
// 스캔 대상(Targets)이 그대로 복원되게 한다.

type storeParam struct {
	Name   string   `json:"name"`
	Ins    []string `json:"ins"`
	Type   string   `json:"type,omitempty"`
	Sample string   `json:"sample,omitempty"`
	Seen   int      `json:"seen,omitempty"`
	Mined  bool     `json:"mined,omitempty"` // 파라미터 마이닝 발견 (이슈 #40)
}

type storeNode struct {
	Segment    string       `json:"segment"`
	Path       string       `json:"path,omitempty"`
	LastPath   string       `json:"last_path,omitempty"`
	Scheme     string       `json:"scheme,omitempty"`
	Methods    []string     `json:"methods,omitempty"`
	Params     []storeParam `json:"params,omitempty"`
	Count      int          `json:"count,omitempty"`
	Auth       bool         `json:"auth,omitempty"`
	Verdict    string       `json:"verdict,omitempty"`
	FirstSeen  string       `json:"first_seen,omitempty"` // 이슈 #7
	LastSeen   string       `json:"last_seen,omitempty"`
	Slugged    bool         `json:"slugged,omitempty"`    // (v1 호환) 형제 클러스터링 상태 — 이슈 #24
	Source     string       `json:"source,omitempty"`     // 출처 신뢰도 등급 (이슈 #25·#26)
	Unverified bool         `json:"unverified,omitempty"` // 라이브니스 프로브 미통과 (이슈 #26)
	AuthOnly   bool         `json:"auth_only,omitempty"`  // 인증 뒤에만 보이는 표면 (이슈 #38)
	Labels     []string     `json:"labels,omitempty"`     // 의미 라벨 (이슈 #41)
	VarChild   string       `json:"var_child,omitempty"`  // 이 자리의 변수 자식 세그먼트 (이슈 #25)
	VarSpec    bool         `json:"var_spec,omitempty"`   // varChild 가 명세 선언인가
	Children   []storeNode  `json:"children,omitempty"`
}

func toStore(n *node) storeNode {
	s := storeNode{
		Segment: n.segment, Path: n.path, LastPath: n.lastPath, Scheme: n.scheme,
		Methods: sortedKeys(n.methods), Count: n.count, Auth: n.auth, Verdict: n.verdict,
		FirstSeen: n.firstSeen, LastSeen: n.lastSeen,
		Source: n.source, Unverified: n.unverified, AuthOnly: n.authOnly, Labels: n.labels, VarChild: n.varChild, VarSpec: n.varSpec,
	}
	pnames := make([]string, 0, len(n.params))
	for name := range n.params {
		pnames = append(pnames, name)
	}
	sort.Strings(pnames)
	for _, name := range pnames {
		agg := n.params[name]
		s.Params = append(s.Params, storeParam{Name: name, Ins: sortedKeys(agg.ins), Type: agg.typ, Sample: agg.sample, Seen: agg.seen, Mined: agg.mined})
	}
	ckeys := make([]string, 0, len(n.children))
	for k := range n.children {
		ckeys = append(ckeys, k)
	}
	sort.Strings(ckeys)
	for _, k := range ckeys {
		s.Children = append(s.Children, toStore(n.children[k]))
	}
	return s
}

func fromStore(s storeNode) *node {
	n := newNode(s.Segment, s.Path)
	n.lastPath, n.scheme, n.count, n.auth, n.verdict = s.LastPath, s.Scheme, s.Count, s.Auth, s.Verdict
	n.firstSeen, n.lastSeen = s.FirstSeen, s.LastSeen
	n.source, n.unverified, n.authOnly = s.Source, s.Unverified, s.AuthOnly
	n.labels = s.Labels
	n.varChild, n.varSpec = s.VarChild, s.VarSpec
	if n.varChild == "" && s.Slugged {
		n.varChild = tplSlug // v1(#24) 저장물 호환: slugged=true → 변수 자식이 {slug}
	}
	for _, m := range s.Methods {
		n.methods[m] = true
	}
	for _, p := range s.Params {
		agg := &paramAgg{ins: map[string]bool{}, typ: p.Type, sample: p.Sample, seen: p.Seen, mined: p.Mined}
		for _, in := range p.Ins {
			agg.ins[in] = true
		}
		n.params[p.Name] = agg
	}
	for _, ch := range s.Children {
		n.children[ch.Segment] = fromStore(ch)
	}
	return n
}

func (t *Tree) storeRoots() []storeNode {
	t.mu.Lock()
	defer t.mu.Unlock()
	hosts := make([]string, 0, len(t.roots))
	for h := range t.roots {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	out := make([]storeNode, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, toStore(t.roots[h]))
	}
	return out
}

func (t *Tree) dump() {
	if t.name == "" {
		return // 테넌트 인메모리 트리 — 파일 안 씀
	}
	data, _ := json.MarshalIndent(t.storeRoots(), "", "  ")
	_ = os.WriteFile(t.name, data, 0644)
}

// Load — 저장 파일에서 트리 복원 (재시작 시 공격면 유지). 인메모리 트리는 무시.
func (t *Tree) Load() {
	if t.name == "" {
		return
	}
	data, err := os.ReadFile(t.name)
	if err != nil {
		return
	}
	var roots []storeNode
	if json.Unmarshal(data, &roots) != nil {
		return
	}
	t.mu.Lock()
	for _, s := range roots {
		// v1 로 저장된 트리를 v2 규칙으로 1회 재분류·병합한다(이슈 #24 하위호환).
		// 파일은 여기서 다시 쓰지 않는다 — 다음 Record 의 dump 때 자연히 갱신된다.
		r := fromStore(s)
		migrateNode(r, true)
		for _, c := range r.children {
			repath(c, "") // 호스트 루트는 path 가 "" — 자식부터 다시 계산
		}
		t.roots[s.Segment] = r
	}
	t.mu.Unlock()
}

// Load — 기본(전역) 트리 복원.
func Load() { def.Load() }

// ── 헬퍼 ──────────────────────────────────────────────────────────

// NormalizePath 는 normalize.go 로 옮겼다 (v2, 이슈 #24).

// inferType — 값에서 타입 추정 (§3 타입추정).
// 숫자·UUID 판정은 경로 세그먼트 분류기(classifyToken)와 규칙을 공유한다(이슈 #24 중복 제거).
// 반환 집합은 v1 그대로 유지한다(int|bool|uuid|email|string) — 저장·표시 계약을 바꾸지 않기 위해.
func inferType(v string) string {
	switch {
	case v == "":
		return "string"
	case v == "true" || v == "false":
		return "bool"
	case reEmail.MatchString(v):
		return "email"
	}
	switch tpl, _ := classifyToken(v); tpl {
	case tplID:
		return "int"
	case tplUUID:
		return "uuid"
	}
	return "string"
}

func first(vs []string) string {
	if len(vs) > 0 {
		return vs[0]
	}
	return ""
}

func splitSegs(p string) []string {
	out := make([]string, 0, 8)
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
