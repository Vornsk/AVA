// Package crawler — 능동 공격면 탐색(Explore, AppScan 대응). 시작 URL에서 링크·폼을
// 따라가며 같은 스코프 내 페이지를 BFS로 크롤해 엔드포인트 트리를 자동으로 채운다.
// 수동 프록시 캡처의 한계(하위 엔드포인트 누락)를 보완한다.
//
//	· 스코프(FR-2.1)·인증주입(FR-2.5)·마스킹은 기존 인스턴스를 재사용
//	· GET 크롤(비파괴). 폼은 엔드포인트로 등록만 하고 제출하지 않음
//	· 페이지 수·깊이 상한, 정규화 경로 기준 중복 제거로 무한 크롤 방지
package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/recon/ingest"
	"proxypoc/internal/scope"
)

// Options — 크롤 상한.
type Options struct {
	MaxPages int    // 가져올 최대 페이지 (기본 200)
	MaxDepth int    // 시작 URL로부터 최대 깊이 (기본 5)
	Mode     string // "static"(기본) | "headless"(Chrome로 JS 렌더 크롤, 옵트인) | "ingest"(명세만, #25)
	NoIngest bool   // true 면 크롤 시작 시의 명세 인제스트를 건너뛴다 (#25, 측정·디버깅용)
}

// Result — 크롤 실행 단위 + 진행률.
type Result struct {
	ID      string `json:"id"`
	Seed    string `json:"seed"`
	Status  string `json:"status"` // 진행 | 완료 | 중단
	Pages   int    `json:"pages"`  // 가져온 페이지 수
	Found   int    `json:"found"`  // 발견한 고유 엔드포인트 수
	JS      int    `json:"js"`     // 분석한 JS 번들 수 (SPA 정적 추출)
	Spec    int    `json:"spec"`   // 명세 인제스트로 등록한 엔드포인트 수 (#25)
	Mode    string `json:"mode"`   // static | headless | ingest
	Queued  int    `json:"queued"` // 남은 큐
	Errors  int    `json:"errors"`
	Started string `json:"started"`
}

type job struct {
	mu     sync.Mutex
	res    Result
	ctx    context.Context
	cancel context.CancelFunc
}

var (
	mu    sync.Mutex
	jobs  = map[string]*job{}
	order []string
	seq   int
)

// Start — 비동기 크롤 시작. 즉시 진행중 Result 반환.
func Start(seed string, opts Options) Result {
	if opts.MaxPages <= 0 {
		opts.MaxPages = 200
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 5
	}
	if opts.Mode == "" {
		opts.Mode = "static"
	}
	mu.Lock()
	seq++
	id := fmt.Sprintf("CR-%d", seq)
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{res: Result{ID: id, Seed: seed, Status: "진행", Mode: opts.Mode, Started: time.Now().Format("2006-01-02 15:04:05")}, ctx: ctx, cancel: cancel}
	jobs[id] = j
	order = append(order, id)
	mu.Unlock()
	switch opts.Mode {
	case "headless":
		go j.runHeadless(seed, opts)
	case "ingest":
		go j.runIngest(seed)
	default:
		go j.run(seed, opts)
	}
	return j.snapshot()
}

// Status — 크롤 상태 조회.
func Status(id string) (Result, bool) {
	mu.Lock()
	j := jobs[id]
	mu.Unlock()
	if j == nil {
		return Result{}, false
	}
	return j.snapshot(), true
}

// Runs — 모든 크롤 실행(생성 순).
func Runs() []Result {
	mu.Lock()
	ids := append([]string(nil), order...)
	mu.Unlock()
	out := make([]Result, 0, len(ids))
	for _, id := range ids {
		if r, ok := Status(id); ok {
			out = append(out, r)
		}
	}
	return out
}

// Cancel — 진행중 크롤 중단.
func Cancel(id string) bool {
	mu.Lock()
	j := jobs[id]
	mu.Unlock()
	if j == nil {
		return false
	}
	j.cancel()
	return true
}

func (j *job) snapshot() Result { j.mu.Lock(); defer j.mu.Unlock(); return j.res }
func (j *job) setStatus(s string) {
	j.mu.Lock()
	if j.res.Status != "중단" {
		j.res.Status = s
	}
	j.mu.Unlock()
}

type item struct {
	u     string
	depth int
}

// ingestOnce — 크롤 시작 시 명세를 1회 인제스트한다 (이슈 #25).
// 링크를 따라가기 전에 대상이 스스로 공개한 경로를 먼저 확보하면, 이후 크롤이 만나는
// 구체값(/users/v1/alice)이 명세가 선언한 변수 자리로 흡수돼 트리가 갈라지지 않는다.
func (j *job) ingestOnce(seed string, opts Options, client *http.Client) {
	if opts.NoIngest || j.ctx.Err() != nil {
		return
	}
	rep := ingest.Run(j.ctx, seed, client)
	j.mu.Lock()
	// 인제스트 요청은 Pages 에 더하지 않는다. MaxPages 는 크롤을 제한하는 예산이지
	// 명세 프로브를 제한하는 값이 아니다 — 더했더니 프로브 18건이 MaxPages=10 을
	// 즉시 소진해 크롤이 첫 페이지에서 멈췄다.
	j.res.Spec = rep.Recorded
	j.res.Found += rep.Recorded
	j.res.Errors += rep.Errors
	j.mu.Unlock()
}

// runIngest — 명세 인제스트만 수행한다 (이슈 #25, profile=ingest).
// 링크 크롤을 돌리지 않으므로 "명세만으로 얼마나 찾는가"가 그대로 측정된다.
func (j *job) runIngest(seed string) {
	client := &http.Client{Timeout: 15 * time.Second}
	rep := ingest.Run(j.ctx, seed, client)
	j.mu.Lock()
	j.res.Pages = rep.Requests // ingest 전용 모드에서는 프로브 수가 곧 요청 수다
	j.res.Spec = rep.Recorded
	j.res.Found = rep.Recorded
	j.res.Errors = rep.Errors
	j.mu.Unlock()
	if j.ctx.Err() != nil {
		j.setStatus("중단")
		return
	}
	j.setStatus("완료")
}

func (j *job) run(seed string, opts Options) {
	client := &http.Client{Timeout: 15 * time.Second}
	j.ingestOnce(seed, opts, client)
	visited := map[string]bool{}
	foundEP := map[string]bool{}
	jsFetched := 0 // 분석한 JS 번들 수(상한 maxJSBundles)
	queue := []item{{seed, 0}}

	for len(queue) > 0 {
		if j.ctx.Err() != nil {
			j.setStatus("중단")
			return
		}
		it := queue[0]
		queue = queue[1:]
		u, err := url.Parse(it.u)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		key := normKey(u)
		if visited[key] || it.depth > opts.MaxDepth {
			continue
		}
		visited[key] = true
		if ok, _ := scope.Allowed(u.Hostname(), u.Path); !ok {
			continue // 스코프 밖 (FR-2.1)
		}

		body, ct, err := j.fetch(client, u)
		j.mu.Lock()
		j.res.Pages++
		pages := j.res.Pages
		j.mu.Unlock()
		if err != nil {
			j.mu.Lock()
			j.res.Errors++
			j.mu.Unlock()
			continue
		}

		// 엔드포인트 등록 (프록시 캡처와 동일 의미)
		recordFound := func(eu *url.URL, source string) {
			recordURL(eu, "GET", source)
			epk := eu.Host + eu.Path
			if !foundEP[epk] {
				foundEP[epk] = true
				j.mu.Lock()
				j.res.Found++
				j.mu.Unlock()
			}
		}
		recordFound(u, endpoints.SrcCrawlLink) // 실제로 따라가 2xx 를 받은 링크

		if pages >= opts.MaxPages {
			break
		}

		if strings.Contains(ct, "html") {
			links, forms := extract(body, u)
			for _, l := range links {
				if lu, e := url.Parse(l); e == nil && !visited[normKey(lu)] {
					queue = append(queue, item{l, it.depth + 1})
				}
			}
			for _, f := range forms {
				recordForm(f, endpoints.SrcCrawlLink)
			}
			// SPA 정적 추출: 인라인 JS + 링크된 JS 번들에서 API 엔드포인트 발굴(등록만, 비파괴).
			for _, ep := range extractAPIEndpoints(body, u) {
				if eu, e := url.Parse(ep); e == nil {
					recordFound(eu, endpoints.SrcStaticRegex) // 정규식 추출물 — 실재 미확인
				}
			}
			for _, s := range scriptSrcs(body, u) {
				if jsFetched >= maxJSBundles {
					break
				}
				su, e := url.Parse(s)
				if e != nil {
					continue
				}
				if ok, _ := scope.Allowed(su.Hostname(), su.Path); !ok {
					continue // 스코프 밖 JS(3rd-party CDN 등) 제외
				}
				jsFetched++
				j.mu.Lock()
				j.res.JS = jsFetched
				j.mu.Unlock()
				jsBody, _, err := j.fetch(client, su)
				if err != nil {
					continue
				}
				for _, ep := range extractAPIEndpoints(jsBody, su) {
					if eu, e := url.Parse(ep); e == nil {
						recordFound(eu, endpoints.SrcStaticRegex) // 정규식 추출물 — 실재 미확인
					}
				}
			}
		}
		j.mu.Lock()
		j.res.Queued = len(queue)
		j.mu.Unlock()
		time.Sleep(120 * time.Millisecond) // rate limit (FR-3.2)
	}
	j.setStatus("완료")
}

// fetch — 인증 주입 후 URL 요청, 본문(최대 1MB)+content-type 반환.
func (j *job) fetch(c *http.Client, u *url.URL) (string, string, error) {
	req, err := http.NewRequestWithContext(j.ctx, "GET", u.String(), nil)
	if err != nil {
		return "", "", err
	}
	auth.Default().Inject(req) // FR-2.5 로그인 상태 크롤
	resp, err := c.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), resp.Header.Get("Content-Type"), nil
}

// recordURL — URL 하나를 엔드포인트 트리에 기록(프록시 DoFunc 과 동일 흐름).
func recordURL(u *url.URL, method, source string) {
	req, _ := http.NewRequest(method, u.String(), nil)
	params := endpoints.ExtractParams(req) // 주입 전 원본 파라미터
	auth.Default().Inject(req)
	authReq := req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != ""
	endpoints.RecordFrom(source, u.Scheme, u.Host, method, u.Path, params, authReq, "")
}

// recordForm — 발견한 폼을 엔드포인트로 등록(제출하지 않음, 비파괴).
func recordForm(f form, source string) {
	fu, err := url.Parse(f.action)
	if err != nil || (fu.Scheme != "http" && fu.Scheme != "https") {
		return
	}
	if ok, _ := scope.Allowed(fu.Hostname(), fu.Path); !ok {
		return
	}
	in := "body"
	if f.method == "GET" {
		in = "query"
	}
	var params []endpoints.Param
	for _, name := range f.fields {
		params = append(params, endpoints.Param{Name: name, In: in})
	}
	// 폼 요청도 인증 동반 여부 반영
	authReq := auth.Default().Enabled()
	endpoints.RecordFrom(source, fu.Scheme, fu.Host, f.method, fu.Path, params, authReq, "")
}

// ── HTML 링크·폼 추출 ──────────────────────────────────────────────

type form struct {
	action string
	method string
	fields []string
}

func extract(body string, base *url.URL) (links []string, forms []form) {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a", "link":
				if abs := resolve(base, attrVal(n, "href")); abs != "" {
					links = append(links, abs)
				}
			case "form":
				f := form{method: strings.ToUpper(attrVal(n, "method"))}
				if f.method == "" {
					f.method = "GET"
				}
				action := attrVal(n, "action")
				if action == "" {
					f.action = stripFragment(base.String())
				} else {
					f.action = resolve(base, action)
				}
				collectFields(n, &f)
				if f.action != "" {
					forms = append(forms, f)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return
}

func collectFields(n *html.Node, f *form) {
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if x.Type == html.ElementNode {
			switch x.Data {
			case "input", "select", "textarea":
				if name := attrVal(x, "name"); name != "" {
					f.fields = append(f.fields, name)
				}
			}
		}
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
}

func attrVal(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

// resolve — 상대/절대 링크를 base 기준 절대 URL로. 프래그먼트·비HTTP 스킴은 버림.
func resolve(base *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") ||
		strings.HasPrefix(strings.ToLower(href), "javascript:") ||
		strings.HasPrefix(strings.ToLower(href), "mailto:") ||
		strings.HasPrefix(strings.ToLower(href), "tel:") ||
		strings.HasPrefix(strings.ToLower(href), "data:") {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(ref)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	abs.Fragment = ""
	return abs.String()
}

func stripFragment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		return s[:i]
	}
	return s
}

// ── SPA 정적 추출: JS 번들·인라인 스크립트에서 API 엔드포인트 발굴 ───────

const (
	maxJSBundles = 20  // 크롤당 분석할 JS 번들 상한(폭주 방지)
	maxEPPerDoc  = 300 // 문서 1개에서 추출할 엔드포인트 상한
)

var (
	// fetch("…") · axios.get('…') · axios("…")
	reCall = regexp.MustCompile("(?i)(?:fetch|axios(?:\\.\\w+)?)\\s*\\(\\s*[\"'`]([^\"'`]+)[\"'`]")
	// jQuery ajax 등 url: "…"
	reAjaxURL = regexp.MustCompile("(?i)\\burl\\s*:\\s*[\"'`]([^\"'`]+)[\"'`]")
	// 따옴표로 감싼 절대경로 /a/b?…  (SPA 라우트·API 경로)
	rePath = regexp.MustCompile("[\"'`](/[a-zA-Z0-9_~][a-zA-Z0-9_\\-./~]*(?:\\?[a-zA-Z0-9_\\-.=&%]*)?)[\"'`]")
	// in-scope 절대 URL
	reURL = regexp.MustCompile(`https?://[a-zA-Z0-9._\-]+(?::\d+)?(?:/[a-zA-Z0-9_\-./~%?=&]*)?`)
	// 정적 에셋(엔드포인트 아님) — 추출 제외.
	assetExt = regexp.MustCompile(`(?i)\.(js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|mp4|webm|mp3|pdf|zip|scss|less)(\?|$)`)
)

// scriptSrcs — HTML에서 <script src> 절대 URL 목록(번들 다운로드용).
func scriptSrcs(body string, base *url.URL) []string {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}
	var out []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			if src := attrVal(n, "src"); src != "" {
				if abs := resolve(base, src); abs != "" {
					out = append(out, abs)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

// extractAPIEndpoints — 텍스트(HTML 인라인 JS 또는 JS 번들)에서 API 엔드포인트를 정규식으로 추출.
// fetch/axios 호출·ajax url·따옴표 절대경로·in-scope 절대 URL을 base 기준으로 해석하고
// 정적 에셋·스코프 밖은 제외, 중복 제거해 반환한다(JS 실행 없이 SPA 공격면 발굴).
func extractAPIEndpoints(text string, base *url.URL) []string {
	seen := map[string]bool{}
	var out []string
	consider := func(raw string) {
		if len(out) >= maxEPPerDoc {
			return
		}
		abs := resolve(base, raw)
		if abs == "" {
			return
		}
		au, err := url.Parse(abs)
		if err != nil || assetExt.MatchString(au.Path) {
			return
		}
		if ok, _ := scope.Allowed(au.Hostname(), au.Path); !ok {
			return
		}
		k := au.Host + au.Path
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, abs)
	}
	for _, m := range reCall.FindAllStringSubmatch(text, -1) {
		consider(m[1])
	}
	for _, m := range reAjaxURL.FindAllStringSubmatch(text, -1) {
		consider(m[1])
	}
	for _, m := range rePath.FindAllStringSubmatch(text, -1) {
		consider(m[1])
	}
	for _, m := range reURL.FindAllString(text, -1) {
		consider(m)
	}
	return out
}

// normKey — 중복 제거 키: host + 정규화 경로 + 정렬된 쿼리 키(값 무시).
// /user/1·/user/2 → 동일, /search?q=a·/search?q=b → 동일 (무한 크롤 방지).
func normKey(u *url.URL) string {
	keys := make([]string, 0)
	for k := range u.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return u.Host + endpoints.NormalizePath(u.Path) + "?" + strings.Join(keys, "&")
}
