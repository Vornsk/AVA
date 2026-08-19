// Package ingest — 정찰 스펙 인제스터 (이슈 #25).
//
// 링크를 따라가는 크롤 대신 대상이 스스로 공개하는 명세를 읽어 엔드포인트를 얻는다.
// OpenAPI 한 파일이면 수백 페이지 크롤보다 정확한 경로+메서드+파라미터+타입을 한 번에 준다.
// 폐쇄망 정적 SPA 대응의 핵심이기도 하다(Chrome 불필요).
//
//	robots.txt / sitemap.xml  → 경로 시드
//	OpenAPI / Swagger         → paths·methods·parameters (타입·required 정확)
//	GraphQL introspection     → 루트 필드
//	JS 소스맵(.map)           → 원본 복원 후 API 경로 재추출
//
// 전부 GET only·비파괴이며 스코프(FR-2.1)로 하드 게이트하고 크롤러와 같은 레이트리밋을 쓴다.
// 등록은 endpoints.RecordSpec 으로 하여 출처 spec 태그가 붙는다(#5 라이브니스 면제 대상).
//
// ★ 상태코드로 판정하지 않는다. SPA 는 없는 경로에도 index.html 을 200 으로 돌려주므로
// (Juice Shop 실측: /openapi.json·/swagger.json·/graphql 전부 200 text/html),
// content-type 과 본문 구조까지 확인해야 없는 명세를 "발견"하지 않는다.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

const (
	rateLimit  = 120 * time.Millisecond // 크롤러와 동일 (FR-3.2)
	maxBody    = 8 << 20                // 소스맵이 크다. 크롤러의 1MB 보다 넉넉히.
	maxSitemap = 20                     // 중첩 sitemap 재귀 상한
	maxPaths   = 2000                   // 한 명세에서 가져올 경로 상한(폭주 방지)
)

// Report — 인제스트 1회 결과.
type Report struct {
	Requests int      `json:"requests"` // 보낸 GET 수
	Recorded int      `json:"recorded"` // 등록한 (method,path) 수
	Sources  []string `json:"sources"`  // 실제로 파싱에 성공한 출처 (openapi:/openapi.json 등)
	Rejected []string `json:"rejected"` // 200 이지만 본문 검증에 걸러진 후보 (SPA catch-all 등)
	Errors   int      `json:"errors"`
	Duration string   `json:"duration"`
}

// openAPICandidates — 후보 프로브. VAmPI 실측상 /openapi.json 만 맞고 나머지는 404 다.
// 순서는 적중률 순. 하나라도 본문 검증을 통과하면 즉시 멈춘다.
var openAPICandidates = []string{
	"/openapi.json", "/swagger.json", "/openapi.yaml", "/openapi.yml",
	"/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json", "/api/openapi.json",
}

var graphQLCandidates = []string{"/graphql", "/api/graphql", "/v1/graphql"}

// Run — seed 호스트에 대해 1회 인제스트한다. 스코프 밖이면 아무것도 하지 않는다.
func Run(ctx context.Context, seed string, client *http.Client) Report {
	start := time.Now()
	rep := Report{}
	base, err := url.Parse(seed)
	if err != nil || base.Host == "" {
		rep.Errors++
		rep.Duration = time.Since(start).String()
		return rep
	}
	ing := &ingester{ctx: ctx, base: base, client: client, rep: &rep, seen: map[string]bool{}}

	ing.robots()
	ing.openAPI()
	ing.graphQL()
	ing.sourceMaps()

	rep.Duration = time.Since(start).String()
	log.Printf("[ING ] %s  요청=%d 등록=%d 출처=%v 걸러냄=%d (%s)",
		base.Host, rep.Requests, rep.Recorded, rep.Sources, len(rep.Rejected), rep.Duration)
	return rep
}

type ingester struct {
	ctx    context.Context
	base   *url.URL
	client *http.Client
	rep    *Report
	seen   map[string]bool // 중복 등록 방지 키 "METHOD path"
}

// get — 스코프 게이트 + 인증 주입 + 레이트리밋을 거쳐 GET. 본문·content-type 반환.
func (g *ingester) get(path string) (body, ctype string, ok bool) {
	u := *g.base
	u.Path = path
	u.RawQuery = ""
	if allowed, _ := scope.Allowed(u.Hostname(), u.Path); !allowed {
		return "", "", false // 스코프 밖으로는 아무것도 내보내지 않는다 (FR-2.1)
	}
	req, err := http.NewRequestWithContext(g.ctx, "GET", u.String(), nil)
	if err != nil {
		g.rep.Errors++
		return "", "", false
	}
	auth.Default().Inject(req)
	time.Sleep(rateLimit)
	resp, err := g.client.Do(req)
	g.rep.Requests++
	if err != nil {
		g.rep.Errors++
		return "", "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false
	}
	return string(b), resp.Header.Get("Content-Type"), true
}

// recordAs — 엔드포인트 하나를 지정한 출처 등급으로 등록한다(중복 제거).
//
// 명세(robots/sitemap/openapi/graphql)는 spec 으로, 소스맵 본문에서 정규식으로 뽑은 추측은
// static-regex 로 등록한다. static-regex 는 라이브니스(#26) 프로브 대상이라, 존재하지 않는
// 추측 경로가 트리에 남지 않는다 — Juice Shop static 실측에서 정규식 추출의 81% 가 오탐이었다.
func (g *ingester) recordAs(source, method, path string, params []endpoints.Param) {
	if path == "" || path[0] != '/' {
		return
	}
	if allowed, _ := scope.Allowed(g.base.Hostname(), path); !allowed {
		return
	}
	key := method + " " + path
	if g.seen[key] {
		return // 이미 더 먼저(더 믿을 만한 출처로) 잡혔다 — 명세가 소스맵보다 앞서 돈다
	}
	g.seen[key] = true
	endpoints.RecordFrom(source, g.base.Scheme, g.base.Host, method, path, params, auth.Default().Enabled(), "")
	g.rep.Recorded++
}

// record — 명세 출처(spec)로 등록. RecordFrom(spec) 은 RecordSpec 과 동치다(변수 자리 선언 포함).
func (g *ingester) record(method, path string, params []endpoints.Param) {
	g.recordAs(endpoints.SrcSpec, method, path, params)
}

// ── robots.txt / sitemap.xml ──────────────────────────────────────

var reSitemapLoc = regexp.MustCompile(`(?is)<loc>\s*([^<\s]+)\s*</loc>`)

func (g *ingester) robots() {
	body, _, ok := g.get("/robots.txt")
	var sitemaps []string
	if ok && !looksLikeHTML(body) {
		found := false
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			lower := strings.ToLower(line)
			switch {
			case strings.HasPrefix(lower, "allow:"), strings.HasPrefix(lower, "disallow:"):
				p := strings.TrimSpace(line[strings.Index(line, ":")+1:])
				if p == "" || p == "/" || strings.ContainsAny(p, "*$") {
					continue // 와일드카드는 경로가 아니다
				}
				g.record("GET", p, nil)
				found = true
			case strings.HasPrefix(lower, "sitemap:"):
				sitemaps = append(sitemaps, strings.TrimSpace(line[strings.Index(line, ":")+1:]))
			}
		}
		if found {
			g.rep.Sources = append(g.rep.Sources, "robots:/robots.txt")
		}
	} else if ok {
		g.rep.Rejected = append(g.rep.Rejected, "robots:/robots.txt (HTML)")
	}

	if len(sitemaps) == 0 {
		sitemaps = []string{"/sitemap.xml"}
	}
	g.sitemaps(sitemaps, 0)
}

// sitemaps — sitemap 을 재귀 파싱한다(sitemapindex 중첩 대응).
func (g *ingester) sitemaps(urls []string, depth int) {
	if depth > 3 {
		return
	}
	for _, raw := range urls {
		if len(g.rep.Sources) > maxSitemap {
			return
		}
		p := raw
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			if u.Hostname() != g.base.Hostname() {
				continue // 다른 호스트의 sitemap 은 따라가지 않는다
			}
			p = u.Path
		}
		body, _, ok := g.get(p)
		if !ok {
			continue
		}
		if looksLikeHTML(body) || !strings.Contains(body, "<loc") {
			g.rep.Rejected = append(g.rep.Rejected, "sitemap:"+p)
			continue
		}
		g.rep.Sources = append(g.rep.Sources, "sitemap:"+p)
		var nested []string
		isIndex := strings.Contains(body, "<sitemapindex")
		for _, m := range reSitemapLoc.FindAllStringSubmatch(body, maxPaths) {
			loc := strings.TrimSpace(m[1])
			if isIndex {
				nested = append(nested, loc)
				continue
			}
			if u, err := url.Parse(loc); err == nil && u.Path != "" {
				if u.Host != "" && u.Hostname() != g.base.Hostname() {
					continue
				}
				g.record("GET", u.Path, nil)
			}
		}
		if len(nested) > 0 {
			g.sitemaps(nested, depth+1)
		}
	}
}

// ── OpenAPI / Swagger ─────────────────────────────────────────────

func (g *ingester) openAPI() {
	for _, cand := range openAPICandidates {
		body, ct, ok := g.get(cand)
		if !ok {
			continue
		}
		spec, err := parseOpenAPI(body, ct)
		if err != nil {
			// 200 이지만 명세가 아니다 — SPA catch-all 이 대부분이다.
			g.rep.Rejected = append(g.rep.Rejected, fmt.Sprintf("openapi:%s (%v)", cand, err))
			continue
		}
		n := g.recordOpenAPI(spec)
		g.rep.Sources = append(g.rep.Sources, "openapi:"+cand)
		log.Printf("[ING ] OpenAPI %s → 엔드포인트 %d", cand, n)
		return // 하나 찾으면 충분하다
	}
}

// recordOpenAPI — 파싱된 명세의 paths 를 등록한다. 등록 수 반환.
func (g *ingester) recordOpenAPI(spec *openAPIDoc) int {
	before := g.rep.Recorded
	prefix := spec.basePath()
	for path, ops := range spec.Paths {
		if !strings.HasPrefix(path, "/") {
			continue
		}
		full := prefix + path
		for method, op := range ops {
			m := strings.ToUpper(method)
			if !isHTTPMethod(m) {
				continue
			}
			g.record(m, full, specParams(op, ops))
		}
	}
	return g.rep.Recorded - before
}

// specParams — operation + path 공통 파라미터를 endpoints.Param 으로. path 파라미터는 경로에
// 이미 반영돼 있으므로 제외하고, query/body 계열만 공격면으로 남긴다.
func specParams(op openAPIOp, ops map[string]openAPIOp) []endpoints.Param {
	var out []endpoints.Param
	add := func(ps []openAPIParam) {
		for _, p := range ps {
			if p.Name == "" || p.In == "path" {
				continue
			}
			in := p.In
			switch in {
			case "query", "cookie":
			case "header":
				continue // 헤더는 공격면 파라미터로 다루지 않는다(기존 캡처와 동일)
			default:
				in = "body"
			}
			out = append(out, endpoints.Param{
				Name:     p.Name,
				In:       in,
				Type:     p.goType(),
				Required: p.Required,
			})
		}
	}
	add(op.Parameters)
	add(op.bodyParams())
	return out
}

func isHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// ── GraphQL introspection ─────────────────────────────────────────

const introspectionQuery = `{"query":"{__schema{queryType{name} mutationType{name}}}"}`

func (g *ingester) graphQL() {
	for _, cand := range graphQLCandidates {
		// introspection 은 POST 가 표준이지만 인제스터는 GET only 이므로 쿼리스트링으로 보낸다.
		body, ct, ok := g.getQuery(cand, "query={__schema{queryType{name}}}")
		if !ok {
			continue
		}
		if !isJSON(ct) || !strings.Contains(body, "__schema") {
			g.rep.Rejected = append(g.rep.Rejected, "graphql:"+cand)
			continue
		}
		var probe struct {
			Data struct {
				Schema json.RawMessage `json:"__schema"`
			} `json:"data"`
		}
		if json.Unmarshal([]byte(body), &probe) != nil || len(probe.Data.Schema) == 0 {
			g.rep.Rejected = append(g.rep.Rejected, "graphql:"+cand)
			continue
		}
		// 스키마가 살아 있다 = GraphQL 엔드포인트다. 경로 자체를 공격면으로 등록한다.
		g.record("POST", cand, []endpoints.Param{{Name: "query", In: "body", Type: "string", Required: true}})
		g.record("GET", cand, []endpoints.Param{{Name: "query", In: "query", Type: "string"}})
		g.rep.Sources = append(g.rep.Sources, "graphql:"+cand)
		return
	}
}

// getQuery — get 과 같지만 쿼리스트링을 붙인다.
func (g *ingester) getQuery(path, rawQuery string) (body, ctype string, ok bool) {
	u := *g.base
	u.Path = path
	u.RawQuery = rawQuery
	if allowed, _ := scope.Allowed(u.Hostname(), u.Path); !allowed {
		return "", "", false
	}
	req, err := http.NewRequestWithContext(g.ctx, "GET", u.String(), nil)
	if err != nil {
		g.rep.Errors++
		return "", "", false
	}
	auth.Default().Inject(req)
	time.Sleep(rateLimit)
	resp, err := g.client.Do(req)
	g.rep.Requests++
	if err != nil {
		g.rep.Errors++
		return "", "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false
	}
	return string(b), resp.Header.Get("Content-Type"), true
}

// ── JS 소스맵 ─────────────────────────────────────────────────────

var (
	reScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	reMapURL    = regexp.MustCompile(`(?m)^//[#@]\s*sourceMappingURL=(\S+)\s*$`)
	reAPIPath   = regexp.MustCompile(`["'\x60](/(?:api|rest|v\d|graphql)[A-Za-z0-9_\-/.{}]*)["'\x60]`)
	// reAbsPathLit — 절대 경로 문자열 리터럴(설정 상수: apiBase: '/config/v2' 등) (이슈 #39).
	reAbsPathLit = regexp.MustCompile(`["'\x60](/[A-Za-z0-9][\w\-./{}:]*)["'\x60]`)
	// reURLInText — 본문·주석 어디서든 절대 URL. 호스트와 경로를 함께 잡아 내부 URL 만 추린다.
	reURLInText = regexp.MustCompile(`https?://([\w.\-]+)(?::\d+)?(/[\w\-./{}:%]*)`)
)

// sourceMaps — 진입 HTML 의 <script src> 를 훑어 소스맵을 수집하고 원본에서 API 경로를 추출한다.
//
// Juice Shop 번들은 sourceMappingURL 주석이 제거돼 있어 주석만 믿으면 하나도 못 찾는다.
// 주석이 있으면 그것을 우선하고, 없으면 "<번들>.map" 관례로 프로브한다.
func (g *ingester) sourceMaps() {
	html, ct, ok := g.get("/")
	if !ok || !strings.Contains(strings.ToLower(ct), "html") {
		return
	}
	found := 0
	for i, m := range reScriptSrc.FindAllStringSubmatch(html, 30) {
		if i >= 10 {
			break // 번들 상한
		}
		src := m[1]
		su, err := url.Parse(src)
		if err != nil || (su.Host != "" && su.Hostname() != g.base.Hostname()) {
			continue // 3rd-party CDN 제외
		}
		bundle := su.Path
		if !strings.HasPrefix(bundle, "/") {
			bundle = "/" + strings.TrimPrefix(bundle, "./")
		}
		js, _, ok := g.get(bundle)
		if !ok {
			continue
		}
		mapPath := bundle + ".map"
		if mm := reMapURL.FindStringSubmatch(js); mm != nil {
			if mu, err := url.Parse(strings.TrimSpace(mm[1])); err == nil && mu.Path != "" && !strings.HasPrefix(mm[1], "data:") {
				if strings.HasPrefix(mu.Path, "/") {
					mapPath = mu.Path
				} else {
					mapPath = dirOf(bundle) + mu.Path
				}
			}
		}
		body, mct, ok := g.get(mapPath)
		if !ok {
			continue
		}
		files, err := parseSourceMap(body, mct)
		if err != nil {
			g.rep.Rejected = append(g.rep.Rejected, "sourcemap:"+mapPath)
			continue
		}
		g.rep.Sources = append(g.rep.Sources, "sourcemap:"+mapPath)
		found++
		// 소스맵 본문은 정규식 추측이라 static-regex 로 등록해 라이브니스 검증을 받게 한다.
		for _, p := range extractFromSources(files, g.base.Hostname()) {
			g.recordAs(endpoints.SrcStaticRegex, "GET", p, nil)
		}
	}
	if found == 0 {
		log.Printf("[ING ] %s 소스맵 없음 (번들에 sourceMappingURL 없고 .map 도 명세 아님)", g.base.Host)
	}
}

// extractFromSources — 복원한 파일들에서 경로 후보를 파일 단위로 뽑는다 (이슈 #39).
// host 는 base 호스트로, 내부 URL 판정에 쓴다("" 면 모든 URL 경로를 내부로 본다).
//
//	· API 경로(/api·/rest·/vN·/graphql) — 프리픽스 앵커라 노이즈가 적어 벤더 포함 전체에서 뽑는다
//	· 프레임워크 라우트(path: '...') — 앱 소스만(벤더 라이브러리의 path: 는 오탐)
//	· 설정 상수·내부 URL — 앱 소스만. 절대 경로 리터럴과 같은 호스트 URL 의 경로부.
func extractFromSources(files []SourceFile, host string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || seen[p] || len(out) >= maxPaths {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, f := range files {
		if f.Content == "" {
			continue
		}
		for _, m := range reAPIPath.FindAllStringSubmatch(f.Content, maxPaths) {
			add(m[1])
		}
		if isVendorSource(f.Path) {
			continue
		}
		for _, p := range composeRoutes(f.Content) {
			add(p)
		}
		for _, p := range extractLoosePaths(f.Content, host) {
			add(p)
		}
	}
	return out
}

// extractLoosePaths — 설정 상수(절대 경로 리터럴)와 내부 URL(같은 호스트)의 경로부를 뽑는다.
// 정적 에셋(.js·.css·.png·.json 등)과 외부 호스트는 제외한다. static-regex 로 등록되므로
// 남는 오탐은 라이브니스가 걸러낸다.
func extractLoosePaths(content, host string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.TrimRight(p, "/")
		if len(p) < 2 || seen[p] || isAssetPath(p) {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, m := range reAbsPathLit.FindAllStringSubmatch(content, maxPaths) {
		add(m[1]) // 설정 상수 — 절대 경로는 본질적으로 같은 오리진
	}
	for _, m := range reURLInText.FindAllStringSubmatch(content, maxPaths) {
		if host != "" && !sameHost(m[1], host) {
			continue // 외부 URL 은 내부 URL 이 아니다
		}
		add(m[2])
	}
	return out
}

// sameHost — u 가 host 와 같거나 그 하위 도메인인가.
func sameHost(u, host string) bool {
	u = strings.ToLower(u)
	host = strings.ToLower(host)
	return u == host || strings.HasSuffix(u, "."+host)
}

// isAssetPath — 마지막 세그먼트 확장자가 정적 자원인가(엔드포인트가 아니다).
func isAssetPath(p string) bool {
	seg := p
	if i := strings.LastIndex(seg, "/"); i >= 0 {
		seg = seg[i+1:]
	}
	dot := strings.LastIndex(seg, ".")
	if dot < 0 {
		return false
	}
	switch strings.ToLower(seg[dot:]) {
	case ".js", ".mjs", ".cjs", ".css", ".scss", ".sass", ".less", ".map",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp4", ".webm", ".mp3", ".wav", ".ogg", ".wasm",
		".json", ".xml", ".txt", ".html", ".htm", ".md", ".csv", ".pdf":
		return true
	}
	return false
}

// composeRoutes — 프레임워크 라우트 정의를 문자열 단위로 훑어 절대 경로를 뽑는다 (이슈 #39).
//
// 평면 정규식은 중첩 라우트를 부모와 못 잇는다 — Angular/Vue 의
//
//	{ path: 'admin', children: [ { path: 'users' }, { path: '' } ] }
//
// 는 /admin/users·/admin 이어야 하는데 정규식만 쓰면 루트급 /users 가 돼 라이브니스가 강등한다.
// 그래서 문자열·주석을 건너뛰며 `[`/`]` 깊이와 `children:` 프리픽스를 추적하는 경량 렉서로 합성한다.
// (원본 소스는 트랜스파일 전이라 라우트 키가 따옴표 없는 리터럴 — 따옴표 키는 대상 밖이다.)
func composeRoutes(content string) []string {
	var out []string
	seen := map[string]bool{}
	emit := func(segs []string) {
		if len(segs) == 0 {
			return
		}
		p := "/" + strings.Join(segs, "/")
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	prefix := map[int][]string{0: nil} // 배열 깊이별 프리픽스(children 배열이 부모 경로를 물려준다)
	lastAbs := map[int][]string{}      // 깊이별 최근 라우트의 절대 경로(자식 프리픽스가 된다)
	depth := 0
	pendingChildren := false // 다음 '[' 가 children 배열인가
	n := len(content)
	for i := 0; i < n; {
		c := content[i]
		switch {
		case c == '/' && i+1 < n && content[i+1] == '/': // 줄 주석
			i += 2
			for i < n && content[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && content[i+1] == '*': // 블록 주석
			i += 2
			for i+1 < n && !(content[i] == '*' && content[i+1] == '/') {
				i++
			}
			i += 2
		case isIdentStart(content, i) && hasWord(content, i, "path"):
			if val, next, ok := readProp(content, i+4); ok {
				if segs, ok := routeSegs(val); ok {
					abs := append(append([]string{}, prefix[depth]...), segs...)
					emit(abs)
					lastAbs[depth] = abs
				}
				i = next
			} else {
				i += 4
			}
		case isIdentStart(content, i) && hasWord(content, i, "children"):
			// children: [ 를 만나면 다음 '[' 를 children 배열로 표시한다.
			if j := skipToArray(content, i+8); j >= 0 {
				pendingChildren = true
				i = j // '[' 위치 — 아래 '[' 케이스가 처리
			} else {
				i += 8
			}
		case c == '\'' || c == '"' || c == '`': // 문자열 리터럴은 데이터 — 통째로 건너뛴다
			i = skipString(content, i)
		case c == '[':
			depth++
			if pendingChildren {
				prefix[depth] = lastAbs[depth-1]
				pendingChildren = false
			} else {
				prefix[depth] = prefix[depth-1]
			}
			delete(lastAbs, depth)
			i++
		case c == ']':
			delete(prefix, depth)
			delete(lastAbs, depth)
			if depth > 0 {
				depth--
			}
			i++
		default:
			i++
		}
	}
	return out
}

// readProp — content[i:] 가 [따옴표]? \s* [:=] \s* "값" 형태면 값과 다음 위치를 돌려준다.
func readProp(content string, i int) (val string, next int, ok bool) {
	n := len(content)
	if i < n && (content[i] == '\'' || content[i] == '"' || content[i] == '`') {
		i++ // 따옴표 키의 닫는 따옴표 (예: "path":)
	}
	i = skipWS(content, i)
	if i >= n || (content[i] != ':' && content[i] != '=') {
		return "", 0, false
	}
	i = skipWS(content, i+1)
	if i >= n || (content[i] != '\'' && content[i] != '"' && content[i] != '`') {
		return "", 0, false
	}
	q := content[i]
	i++
	start := i
	for i < n && content[i] != q {
		if content[i] == '\\' {
			i++
		}
		i++
	}
	return content[start:i], i + 1, true
}

// skipToArray — content[i:] 가 [따옴표]? \s* [:=] \s* [ 로 이어지면 '[' 위치를, 아니면 -1.
func skipToArray(content string, i int) int {
	n := len(content)
	if i < n && (content[i] == '\'' || content[i] == '"' || content[i] == '`') {
		i++
	}
	i = skipWS(content, i)
	if i >= n || (content[i] != ':' && content[i] != '=') {
		return -1
	}
	i = skipWS(content, i+1)
	if i < n && content[i] == '[' {
		return i
	}
	return -1
}

func skipString(content string, i int) int {
	n := len(content)
	q := content[i]
	i++
	for i < n && content[i] != q {
		if content[i] == '\\' {
			i++
		}
		i++
	}
	return i + 1
}

func skipWS(content string, i int) int {
	for i < len(content) && (content[i] == ' ' || content[i] == '\t' || content[i] == '\n' || content[i] == '\r') {
		i++
	}
	return i
}

func isWordChar(b byte) bool {
	return b == '_' || b == '$' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// isIdentStart — content[i] 앞이 식별자 문자가 아니어야 키워드 시작이다(filepath 의 path 배제).
func isIdentStart(content string, i int) bool {
	return i == 0 || !isWordChar(content[i-1])
}

// hasWord — content[i:] 가 word 로 시작하고 그 뒤가 식별자 문자가 아닌가(pathname 배제는 readProp 이 담당).
func hasWord(content string, i int, word string) bool {
	return i+len(word) <= len(content) && strings.EqualFold(content[i:i+len(word)], word)
}

// routeSegs — 라우트 값 하나를 정규화된 세그먼트로 쪼갠다. 정적 경로가 아니면 (nil,false).
// 빈 값("")은 (빈 슬라이스,true) — 자식 라우트의 기본 경로(부모와 동일)를 뜻한다.
//
//	· 외부 URL·프로토콜 상대·보간식(${}·표현식)은 정적 경로가 아니다 → 버린다
//	· :id → {id} (트리의 변수 자리 규칙과 맞춘다) · 후행 ? (optional) 제거
//	· 와일드카드(* · **) 자리에서 멈춘다 — 뒤 세그먼트는 의미가 없다
func routeSegs(v string) ([]string, bool) {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "://") || strings.HasPrefix(v, "//") {
		return nil, false
	}
	if strings.ContainsAny(v, " \t<>(){}$|\\") {
		return nil, false // 표현식·보간·JSX 는 정적 경로가 아니다
	}
	var segs []string
	for _, s := range strings.Split(v, "/") {
		if s == "" {
			continue
		}
		if s == "*" || s == "**" {
			break
		}
		if strings.HasPrefix(s, ":") {
			name := strings.TrimRight(s[1:], "?")
			if name == "" {
				name = "param"
			}
			s = "{" + name + "}"
		}
		segs = append(segs, s)
	}
	return segs, true
}

// cleanRoute — 라우트 값 하나를 등록 가능한 절대 경로로. 비거나 라우트가 아니면 (,false).
// 앞에 / 를 붙인다(Angular 자식 라우트는 상대 경로라 슬래시가 없다).
func cleanRoute(v string) (string, bool) {
	segs, ok := routeSegs(v)
	if !ok || len(segs) == 0 {
		return "", false
	}
	return "/" + strings.Join(segs, "/"), true
}

// isVendorSource — 소스맵 원본 경로가 서드파티(node_modules)·번들러 런타임인가.
// 프레임워크 라우트 추출에서 제외한다(라이브러리 내부 path: 가 오탐을 만든다).
func isVendorSource(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "node_modules") ||
		strings.Contains(p, "/webpack/") ||
		strings.HasPrefix(p, "webpack/") ||
		strings.Contains(p, "/vendor")
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i+1]
	}
	return "/"
}

// looksLikeHTML — SPA catch-all 판정. 상태코드 대신 본문으로 본다.
func looksLikeHTML(body string) bool {
	head := strings.ToLower(strings.TrimSpace(body))
	if len(head) > 512 {
		head = head[:512]
	}
	return strings.Contains(head, "<!doctype html") || strings.Contains(head, "<html") ||
		strings.Contains(head, "<!--") && strings.Contains(head, "<meta")
}

func isJSON(ct string) bool { return strings.Contains(strings.ToLower(ct), "json") }
