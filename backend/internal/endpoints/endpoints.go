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
	"regexp"
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
}

type paramAgg struct {
	ins    map[string]bool
	typ    string
	sample string
	seen   int // 이 파라미터가 등장한 요청 수
}

type node struct {
	segment   string
	path      string
	lastPath  string // 마지막으로 본 concrete 경로 (스캔 재요청용)
	scheme    string // http | https (스캔 재요청 시 원 스킴 보존)
	methods   map[string]bool
	params    map[string]*paramAgg
	count     int
	auth      bool
	verdict   string
	firstSeen string // 최초 캡처 시각 (RFC3339, FR-2.4 조회 강화 — 이슈 #7)
	lastSeen  string // 최근 캡처 시각 (RFC3339)
	children  map[string]*node
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

var (
	def = &Tree{roots: map[string]*node{}, name: "endpoints.json"} // 기본(전역) 트리

	reUUID  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
)

// Default — 기본(전역) 트리.
func Default() *Tree { return def }

// ── 전역 위임 함수 (하위호환, :8080 공유 프록시) ──
func Record(scheme, host, method, rawPath string, params []Param, auth bool, verdict string) {
	def.Record(scheme, host, method, rawPath, params, auth, verdict)
}
func Snapshot() []OutNode                    { return def.Snapshot() }
func Find(host, path string) (OutNode, bool) { return def.Find(host, path) }
func Targets() []Target                      { return def.Targets() }
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
	cur := root
	acc := ""
	for _, s := range splitSegs(norm) {
		acc += "/" + s
		ch, ok := cur.children[s]
		if !ok {
			ch = newNode(s, acc)
			cur.children[s] = ch
		}
		cur = ch
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
	t.mu.Unlock()

	log.Printf("[EP  ] %s %s  methods=%v params=%d auth=%v", host, norm, method, len(params), auth)
	t.dump()
}

// OutNode — 트리 출력(JSON·MCP·파일).
type OutNode struct {
	Segment   string    `json:"segment"`
	Path      string    `json:"path,omitempty"`
	Methods   []string  `json:"methods,omitempty"`
	Params    []Param   `json:"params,omitempty"`
	Count     int       `json:"count,omitempty"`
	Auth      bool      `json:"auth_required,omitempty"`
	Verdict   string    `json:"verdict,omitempty"`
	FirstSeen string    `json:"first_seen,omitempty"` // 최초 캡처 시각 (이슈 #7)
	LastSeen  string    `json:"last_seen,omitempty"`  // 최근 캡처 시각
	Children  []OutNode `json:"children,omitempty"`
}

func toOut(n *node) OutNode {
	o := OutNode{
		Segment:   n.segment,
		Path:      n.path,
		Methods:   sortedKeys(n.methods),
		Params:    outParams(n),
		Count:     n.count,
		Auth:      n.auth,
		Verdict:   n.verdict,
		FirstSeen: n.firstSeen,
		LastSeen:  n.lastSeen,
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
	root, ok := t.roots[host]
	if !ok {
		return OutNode{}, false
	}
	cur := root
	for _, s := range splitSegs(path) {
		ch, ok := cur.children[s]
		if !ok {
			return OutNode{}, false
		}
		cur = ch
	}
	o := toOut(cur)
	o.Children = nil
	return o, true
}

// Target — 스캔 대상 엔드포인트 (concrete 경로 포함).
type Target struct {
	Scheme    string   `json:"scheme,omitempty"` // http | https (스캔 재요청용)
	Host      string   `json:"host"`             // authority (host[:port])
	Path      string   `json:"path"`             // concrete (재요청 가능)
	Methods   []string `json:"methods,omitempty"`
	Params    []Param  `json:"params,omitempty"`
	Auth      bool     `json:"auth_required"`         // 정상 접근 시 인증을 동반했는가 (접근통제 판정 힌트)
	Verdict   string   `json:"verdict,omitempty"`     // 위험 판단 결과 (§5.2; 자동 대상선정 힌트, FR-3.9)
	Count     int      `json:"count,omitempty"`       // 누적 히트 수 (조회 강화 — 이슈 #7)
	FirstSeen string   `json:"first_seen,omitempty"`  // 최초 캡처 시각 (RFC3339)
	LastSeen  string   `json:"last_seen,omitempty"`   // 최근 캡처 시각 (RFC3339)
}

// Interesting — 공격면이 넓은 대상인가 (파라미터/인증/위험판단 존재). FR-3.9 자동선정용.
func (t Target) Interesting() bool {
	return len(t.Params) > 0 || t.Auth || t.Verdict != ""
}

// Targets — 스캔 대상 목록 (메서드가 있는 실제 엔드포인트만).
func (t *Tree) Targets() []Target {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Target
	var walk func(host string, n *node)
	walk = func(host string, n *node) {
		if len(n.methods) > 0 && n.lastPath != "" {
			out = append(out, Target{
				Scheme:    n.scheme,
				Host:      host,
				Path:      n.lastPath,
				Methods:   sortedKeys(n.methods),
				Params:    outParams(n),
				Auth:      n.auth,
				Verdict:   n.verdict,
				Count:     n.count,
				FirstSeen: n.firstSeen,
				LastSeen:  n.lastSeen,
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
			Required: agg.seen == n.count,
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
}

type storeNode struct {
	Segment   string       `json:"segment"`
	Path      string       `json:"path,omitempty"`
	LastPath  string       `json:"last_path,omitempty"`
	Scheme    string       `json:"scheme,omitempty"`
	Methods   []string     `json:"methods,omitempty"`
	Params    []storeParam `json:"params,omitempty"`
	Count     int          `json:"count,omitempty"`
	Auth      bool         `json:"auth,omitempty"`
	Verdict   string       `json:"verdict,omitempty"`
	FirstSeen string       `json:"first_seen,omitempty"` // 이슈 #7
	LastSeen  string       `json:"last_seen,omitempty"`
	Children  []storeNode  `json:"children,omitempty"`
}

func toStore(n *node) storeNode {
	s := storeNode{
		Segment: n.segment, Path: n.path, LastPath: n.lastPath, Scheme: n.scheme,
		Methods: sortedKeys(n.methods), Count: n.count, Auth: n.auth, Verdict: n.verdict,
		FirstSeen: n.firstSeen, LastSeen: n.lastSeen,
	}
	pnames := make([]string, 0, len(n.params))
	for name := range n.params {
		pnames = append(pnames, name)
	}
	sort.Strings(pnames)
	for _, name := range pnames {
		agg := n.params[name]
		s.Params = append(s.Params, storeParam{Name: name, Ins: sortedKeys(agg.ins), Type: agg.typ, Sample: agg.sample, Seen: agg.seen})
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
	for _, m := range s.Methods {
		n.methods[m] = true
	}
	for _, p := range s.Params {
		agg := &paramAgg{ins: map[string]bool{}, typ: p.Type, sample: p.Sample, seen: p.Seen}
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
		t.roots[s.Segment] = fromStore(s)
	}
	t.mu.Unlock()
}

// Load — 기본(전역) 트리 복원.
func Load() { def.Load() }

// ── 헬퍼 ──────────────────────────────────────────────────────────

// NormalizePath — 숫자로만 된 세그먼트를 {id}로 치환해 중복 제거.
// 엔드포인트 트리와 LLM 토큰최소화 dedup(FR-2.3)이 공용으로 쓴다.
func NormalizePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s != "" && isAllDigits(s) {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
}

// inferType — 값에서 타입 추정 (§3 타입추정).
func inferType(v string) string {
	switch {
	case v == "":
		return "string"
	case isAllDigits(v):
		return "int"
	case v == "true" || v == "false":
		return "bool"
	case reUUID.MatchString(v):
		return "uuid"
	case reEmail.MatchString(v):
		return "email"
	default:
		return "string"
	}
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
