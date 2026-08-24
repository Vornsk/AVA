// Package detector — 진단 Detector (§2.1 플러그인, §5.3). 대상 엔드포인트를 검사해 Finding 생성.
// 내장: 보안헤더 누락 / 반사입력(XSS 후보) / 민감정보 노출 / (데모)파괴적.
// 요청은 인증 주입(FR-2.5)을 재사용해 로그인 상태로 능동 점검. 증적은 마스킹.
package detector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/finding"
	"proxypoc/internal/masking"
	"proxypoc/internal/payload"
)

// 스캔 요청 rate limit (FR-3.2 가드레일): 대상 서버를 몰아치지 않도록 간격 유지.
var (
	rlMu    sync.Mutex
	nextReq time.Time
	minGap  = 150 * time.Millisecond
)

func throttle() {
	rlMu.Lock()
	now := time.Now()
	start := now
	if nextReq.After(now) {
		start = nextReq
	}
	nextReq = start.Add(minGap)
	wait := start.Sub(now)
	rlMu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

// SetRateGap — 스캔 요청 최소 간격 조정 (safe-mode에서 강화, FR-3.2).
func SetRateGap(d time.Duration) {
	if d <= 0 {
		return
	}
	rlMu.Lock()
	minGap = d
	rlMu.Unlock()
}

// Detector — 대상을 검사해 finding을 낸다.
// inj 는 이 진단 컨텍스트(테넌트/프로젝트)의 인증 주입기 — 능동 요청을 로그인 상태로 보내고
// 다중 신원을 조회한다(§5.1 멀티테넌시 Phase 2: 전역 auth 대신 주입).
type Detector interface {
	ID() string
	Name() string
	Destructive() bool // 파괴성 항목은 기본 제외(FR-3.2)
	Detect(ctx context.Context, t endpoints.Target, client *http.Client, inj *auth.Injector) []finding.Finding
}

// All — 내장 Detector 목록.
func All() []Detector {
	return []Detector{
		securityHeaders{},
		reflectedInput{},
		storedXSS{},
		domXSS{},
		sensitiveData{},
		multiIdentity{},
		verticalPrivEsc{},
		sqlInjection{},
		blindSQLi{},
		timeBlindSQLi{},
		pathTraversal{},
		openRedirect{},
		cmdInjection{},
		ssrf{},
		ssti{},
		xxe{},
		ldapInjection{},
		ssiInjection{},
		csrfMissing{},
		fileUpload{},
		cookieSecurity{},
		httpMethod{},
		dirIndexing{},
		opensslTLSTool{}, // 외부 도구 어댑터 (FR-3.4)
		sslscanTool{},
		destructiveDemo{},
	}
}

// Info — Detector 카탈로그 항목 (MCP list_detectors, FR-3.1 항목 선택용).
type Info struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Destructive bool   `json:"destructive"`
	Tool        string `json:"tool,omitempty"`      // 외부 도구 기반이면 도구명 (FR-3.4)
	Available   *bool  `json:"available,omitempty"` // 외부 도구 설치 여부
	Version     string `json:"version,omitempty"`   // 도구 버전
}

// Catalog — 사용 가능한 Detector 목록. 외부 도구는 존재·버전 포함.
func Catalog() []Info {
	var out []Info
	for _, d := range All() {
		info := Info{ID: d.ID(), Name: d.Name(), Destructive: d.Destructive()}
		if tb, ok := d.(ToolBased); ok {
			avail, ver := tb.Available()
			info.Tool = tb.Tool()
			info.Available = &avail
			info.Version = ver
		}
		out = append(out, info)
	}
	return out
}

// Select — id 목록으로 Detector 필터. 비면 전체.
func Select(ids []string) []Detector {
	if len(ids) == 0 {
		return All()
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []Detector
	for _, d := range All() {
		if want[d.ID()] {
			out = append(out, d)
		}
	}
	return out
}

// fetch — rate limit 후 인증 주입 요청, 응답+본문(최대 1MB) 반환. 세션 만료 시 자동 재로그인·재시도.
func fetch(ctx context.Context, client *http.Client, inj *auth.Injector, method, rawURL string) (*http.Response, string, error) {
	return doInjected(ctx, client, inj, probe{method: method, url: rawURL})
}

// doInjected — probe 요청 실행 + 세션 지속성(FR-2.5): 응답이 로그아웃으로 보이고 재로그인 절차가
// 설정돼 있으면 재로그인 후 1회 재시도한다.
func doInjected(ctx context.Context, client *http.Client, inj *auth.Injector, pr probe) (*http.Response, string, error) {
	resp, body, err := doOnce(ctx, client, inj, pr)
	if err != nil {
		return resp, body, err
	}
	if inj.LoginEnabled() && inj.LooksLoggedOut(resp.Header.Get("Location"), body) {
		if inj.Relogin(client) {
			log.Printf("[SCAN] 세션 만료 감지 → 재로그인 후 재시도: %s", masking.Mask(pr.url))
			return doOnce(ctx, client, inj, pr)
		}
	}
	return resp, body, err
}

// doOnce — rate limit + 인증 주입 요청 1회.
func doOnce(ctx context.Context, client *http.Client, inj *auth.Injector, pr probe) (*http.Response, string, error) {
	throttle() // FR-3.2 rate limit
	req, err := newProbeReq(ctx, pr)
	if err != nil {
		return nil, "", err
	}
	inj.Inject(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(body), nil
}

// fetchAs — 특정 신원의 쿠키·헤더로 요청 (다중 신원 교차 요청용).
func fetchAs(ctx context.Context, client *http.Client, method, rawURL string, id auth.Identity) (*http.Response, string, error) {
	throttle()
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	id.Apply(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(body), nil
}

func urlOf(t endpoints.Target) string {
	scheme := t.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + t.Host + t.Path
}

// reqLine — 재현 요청 라인(마스킹). 증적 FR-4.2.
func reqLine(method, rawURL string) string { return method + " " + masking.Mask(rawURL) }

// snippet — 증명 응답 스니펫: match 주변 ±radius 를 한 줄로 잘라 마스킹.
// match 가 비면 응답 앞부분. 값 유출 방지를 위해 반드시 Mask 를 거친다.
func snippet(body, match string) string {
	const radius = 80
	oneLine := strings.Join(strings.Fields(body), " ") // 공백·개행 정규화
	if match != "" {
		if m := strings.Join(strings.Fields(match), " "); m != "" {
			if i := strings.Index(oneLine, m); i >= 0 {
				start := i - radius
				if start < 0 {
					start = 0
				}
				end := i + len(m) + radius
				if end > len(oneLine) {
					end = len(oneLine)
				}
				return masking.Mask(oneLine[start:end])
			}
		}
	}
	if len(oneLine) > 180 {
		oneLine = oneLine[:180]
	}
	return masking.Mask(oneLine)
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// 비실행 컨테이너: 안에 반사돼도 스크립트로 실행되지 않는 HTML 요소.
var inertContainers = []struct{ open, close string }{
	{"<!--", "-->"}, {"<textarea", "</textarea"}, {"<title", "</title"},
	{"<style", "</style"}, {"<xmp", "</xmp"},
}

// reflectionExecutable — body 안 pl 반사 위치가 실행 가능한 컨텍스트인가.
// 반사 지점 직전에 열려서 아직 안 닫힌 비실행 컨테이너가 있으면 false(오탐 배제).
func reflectionExecutable(body, pl string) bool {
	i := strings.Index(body, pl)
	if i < 0 {
		return false
	}
	before := strings.ToLower(body[:i])
	for _, c := range inertContainers {
		if lo := strings.LastIndex(before, c.open); lo >= 0 && !strings.Contains(before[lo:], c.close) {
			return false // 열린 비실행 컨테이너 안에 반사됨
		}
	}
	return true
}

// 동적 콘텐츠(토큰·타임스탬프·세션·긴 hex/숫자)를 제거해 응답 비교를 견고하게.
// idor/privesc/블라인드 SQLi 의 차등 비교가 CSRF 토큰·시각 등으로 깨지지 않게 한다.
var volatileContent = regexp.MustCompile(`(?i)(csrf|xsrf|nonce|_?token|jsessionid|phpsessid|sessionid|\bsid)["'=:\s]*[0-9a-z._-]{6,}` +
	`|\d{4}-\d{2}-\d{2}[t ][\d:.]+` + // ISO 타임스탬프
	`|\b[0-9a-f]{16,}\b` + // 긴 hex(토큰·해시)
	`|\b\d{10,}\b`) // 긴 숫자(epoch 등)

func normalizeBody(s string) string { return volatileContent.ReplaceAllString(s, "") }

// ── 1) 보안 헤더 누락 (rule, 비파괴) ──────────────────────────────
type securityHeaders struct{}

func (securityHeaders) ID() string        { return "sec-headers" }
func (securityHeaders) Name() string      { return "미흡한 보안 헤더" }
func (securityHeaders) Destructive() bool { return false }

func (securityHeaders) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	resp, _, err := fetch(ctx, c, inj, "GET", urlOf(t))
	if err != nil {
		return nil
	}
	want := []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"}
	var missing []string
	for _, h := range want {
		if resp.Header.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []finding.Finding{{
		Vuln: "미흡한 보안 헤더", Severity: "low", Host: t.Host, Path: t.Path, Method: "GET",
		Kind: "rule", Detector: "sec-headers", Confidence: "high",
		Evidence:    "누락: " + strings.Join(missing, ", "),
		Request:     reqLine("GET", urlOf(t)),
		Response:    "응답에 보안 헤더 없음: " + strings.Join(missing, ", "),
		RespCode:    resp.StatusCode,
		ContentType: ctype(resp),
	}}
}

// ── 2) 반사된 입력값 = XSS 후보 (rule, 비파괴) ────────────────────
type reflectedInput struct{}

func (reflectedInput) ID() string        { return "reflected-input" }
func (reflectedInput) Name() string      { return "반사된 입력값(XSS 후보)" }
func (reflectedInput) Destructive() bool { return false }

func (reflectedInput) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	for _, p := range t.Params {
		if !injectable(p) {
			continue
		}
		for _, pl := range payload.XSS() { // 버전관리 페이로드셋 (FR-3.7)
			pr, ok := buildProbe(t, p, pl)
			if !ok {
				continue
			}
			resp, body, err := fetchProbe(ctx, c, inj, pr)
			if err != nil {
				continue
			}
			// ★ 미디어타입 검증 (이슈 #54). 브라우저가 마크업으로 렌더링하지 않는 응답
			// (text/plain·application/json·text/csv…)에 반사된 값은 실행되지 않으므로 XSS 가 아니다.
			// #49 벤치의 오탐 5건이 전부 이 유형이었다 — P 82.8% 를 깎아먹던 단일 원인.
			// content-type 미상이면 브라우저가 스니핑하므로 보고한다(정탐 삭제 회피).
			if !rendersMarkup(ctype(resp)) {
				continue
			}
			// 컨텍스트 검증: 페이로드가 raw 로 반사되고(인코딩 시 미일치) + 실행 가능한 위치일 것.
			// 주석·textarea·title 등 비실행 컨테이너 안의 반사는 XSS 로 실행되지 않으므로 제외(오탐 감소).
			if strings.Contains(body, pl) && reflectionExecutable(body, pl) {
				out = append(out, finding.Finding{
					Vuln: "반사된 입력값(XSS 후보)", Severity: "medium", Host: t.Host, Path: t.Path, Method: pr.method,
					Param: p.Name, Kind: "rule", Detector: "reflected-input", Confidence: "high",
					Evidence:    "파라미터 " + p.Name + "(" + p.In + ") 의 페이로드가 실행 가능한 컨텍스트에 인코딩 없이 반사됨",
					Request:     probeLine(pr),
					Response:    snippet(body, pl),
					RespCode:    resp.StatusCode,
					ContentType: ctype(resp),
				})
				break // 파라미터당 1건이면 충분
			}
		}
	}
	return out
}

// ── 2b) 저장형 XSS (rule, 파괴적 — 데이터 저장 부작용) ─────────────
// 반사형과 구분: 고유 마커를 주입한 뒤, 마커를 담지 않은 "클린" 재조회 응답에
// 마커가 실행 가능하게 나타나면 서버에 저장(persist)된 것 → 저장형 XSS.
type storedXSS struct{}

func (storedXSS) ID() string        { return "stored-xss" }
func (storedXSS) Name() string      { return "저장형 XSS(Stored XSS)" }
func (storedXSS) Destructive() bool { return true } // 대상에 데이터를 저장하므로 옵트인(파괴적)

var storedNonce uint64

func (storedXSS) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	displayURL := urlOf(t) // 표시 페이지 = 대상 자신(GET)
	for _, p := range t.Params {
		n := atomic.AddUint64(&storedNonce, 1)
		// 고유·실행가능 마커 (반사형 페이로드셋과 독립, 스테일 데이터 오탐 방지).
		marker := fmt.Sprintf("<img src=x onerror=stx%d()>", n)

		var injected bool
		switch {
		case strings.Contains(p.In, "query"):
			if u, ok := injectQuery(t, p.Name, marker); ok {
				if _, _, err := fetch(ctx, c, inj, "GET", u); err == nil {
					injected = true
				}
			}
		case strings.Contains(p.In, "body") || strings.Contains(p.In, "form"):
			if postForm(ctx, c, inj, urlOf(t), t, p.Name, marker) {
				injected = true
			}
		}
		if !injected {
			continue
		}
		// 클린 재조회 — 요청에 마커가 없는데도 응답에 실행가능하게 남아있으면 저장형.
		cresp, clean, err := fetch(ctx, c, inj, "GET", displayURL)
		if err != nil {
			continue
		}
		// 반사형과 같은 미디어타입 검증 (이슈 #54) — 렌더링 안 되면 저장돼 있어도 실행되지 않는다.
		if !rendersMarkup(ctype(cresp)) {
			continue
		}
		if strings.Contains(clean, marker) && reflectionExecutable(clean, marker) {
			out = append(out, finding.Finding{
				Vuln: "저장형 XSS(Stored XSS)", Severity: "high", Host: t.Host, Path: t.Path, Method: "GET",
				Param: p.Name, Kind: "rule", Detector: "stored-xss", Confidence: "high",
				Evidence: "파라미터 " + p.Name + " 로 주입한 페이로드가 마커 없는 재조회 응답에 실행 가능하게 저장·반사됨",
				Request:  reqLine("GET", displayURL),
				Response: snippet(clean, marker),
				RespCode: cresp.StatusCode, ContentType: ctype(cresp),
			})
			break // 파라미터당 1건
		}
	}
	return out
}

// postForm — 폼/바디 파라미터에 값을 넣어 POST(저장 유도). 캡처된 형제 파라미터 샘플을 보존한다.
func postForm(ctx context.Context, c *http.Client, inj *auth.Injector, rawURL string, t endpoints.Target, name, val string) bool {
	form := url.Values{}
	for _, p := range t.Params {
		if strings.Contains(p.In, "body") || strings.Contains(p.In, "form") {
			if p.Name == name {
				form.Set(p.Name, val)
			} else if p.Sample != "" {
				form.Set(p.Name, p.Sample)
			}
		}
	}
	if form.Get(name) == "" {
		form.Set(name, val)
	}
	throttle()
	req, err := http.NewRequestWithContext(ctx, "POST", rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	inj.Inject(req)
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return true
}

// ── 2c) DOM 기반 XSS (rule, 비파괴 — 정적 힌트) ───────────────────
// JS 실행 엔진이 없으므로 확증이 아닌 정적 힌트: 동일 <script> 블록 안에서
// 사용자 제어 source(location.hash 등)가 위험 sink(innerHTML/eval 등)로 흐를 가능성 → 수동 검토 후보.
type domXSS struct{}

func (domXSS) ID() string        { return "dom-xss" }
func (domXSS) Name() string      { return "DOM 기반 XSS(정적 힌트)" }
func (domXSS) Destructive() bool { return false }

var (
	domSources = []string{"location.hash", "location.search", "location.href", "document.url", "document.referrer", "window.name", "location.pathname", "document.location"}
	domSinks   = []string{".innerhtml", ".outerhtml", "document.write", "document.writeln", ".insertadjacenthtml", "eval(", "settimeout(", "setinterval(", ".html(", "new function("}
	scriptRe   = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
)

func (domXSS) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	resp, body, err := fetch(ctx, c, inj, "GET", urlOf(t))
	if err != nil {
		return nil
	}
	for _, m := range scriptRe.FindAllStringSubmatch(body, -1) {
		code := strings.ToLower(m[1])
		src := firstContains(code, domSources)
		sink := firstContains(code, domSinks)
		if src == "" || sink == "" {
			continue
		}
		return []finding.Finding{{
			Vuln: "DOM 기반 XSS(정적 힌트)", Severity: "medium", Host: t.Host, Path: t.Path, Method: "GET",
			Kind: "rule", Detector: "dom-xss", Confidence: "low", // 정적 힌트 — 수동 확증 필요
			Evidence:    fmt.Sprintf("스크립트에서 사용자 제어 source '%s' → 위험 sink '%s' 흐름 가능(수동 검토)", src, sink),
			Request:     reqLine("GET", urlOf(t)),
			Response:    snippet(m[1], ""),
			RespCode:    resp.StatusCode,
			ContentType: ctype(resp),
		}}
	}
	return nil
}

// firstContains — cands 중 s에 포함된 첫 항목("" = 없음).
func firstContains(s string, cands []string) string {
	for _, c := range cands {
		if strings.Contains(s, c) {
			return c
		}
	}
	return ""
}

// ── 3) 민감정보 노출 (rule, 비파괴) ──────────────────────────────
type sensitiveData struct{}

func (sensitiveData) ID() string        { return "sensitive-data" }
func (sensitiveData) Name() string      { return "민감정보 노출" }
func (sensitiveData) Destructive() bool { return false }

func (sensitiveData) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	resp, body, err := fetch(ctx, c, inj, "GET", urlOf(t))
	if err != nil {
		return nil
	}
	kinds, at := payload.FindSensitiveAt(body)
	if len(kinds) == 0 {
		return nil
	}
	return []finding.Finding{{
		Vuln: "민감정보 노출", Severity: "high", Host: t.Host, Path: t.Path, Method: "GET",
		Kind: "rule", Detector: "sensitive-data", Confidence: "high",
		Evidence:    "응답에서 발견: " + strings.Join(kinds, ", "),
		Request:     reqLine("GET", urlOf(t)),
		Response:    snippet(body, at), // 마스킹되어 실제 값은 가려짐
		RespCode:    resp.StatusCode,
		ContentType: ctype(resp),
	}}
}

// ── 4) 다중 신원 접근통제 / IDOR (rule, 비파괴, FR-3.6) ───────────
type multiIdentity struct{}

func (multiIdentity) ID() string        { return "idor" }
func (multiIdentity) Name() string      { return "다중 신원 접근통제(IDOR/권한)" }
func (multiIdentity) Destructive() bool { return false }

// 특권 경로(명백한 관리/내부 기능) — 인증 없이 노출되면 접근통제 미흡. rules 가드레일과 별개의 탐지 신호.
// 일반 사용자 경로(/user/42, /settings 등) 오탐을 피하려 관리성 세그먼트로 한정.
var privilegedPath = regexp.MustCompile(`(?i)/(admin(istrator)?|manage(ment)?|internal|console|sysadmin|superuser)(/|$)`)

func (multiIdentity) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	ids := inj.Identities()
	if len(ids) < 2 {
		return nil // 비교하려면 anon + 최소 1개 신원 필요
	}

	type res struct {
		name   string
		status int
		hash   string
		ok     bool
	}
	var results []res
	var anon res
	var anonSeen bool
	for _, id := range ids {
		resp, body, err := fetchAs(ctx, c, "GET", urlOf(t), id)
		if err != nil {
			continue
		}
		r := res{id.Name, resp.StatusCode, hash12(normalizeBody(body)), resp.StatusCode >= 200 && resp.StatusCode < 300}
		results = append(results, r)
		if id.Name == "anon" {
			anon, anonSeen = r, true
		}
	}

	// 인증 신원(비-anon)만: 실제로 로그인해 2xx 를 받은 것들.
	var named []res
	for _, r := range results {
		if r.name != "anon" && r.ok {
			named = append(named, r)
		}
	}

	var out []finding.Finding

	// (1) 특권 경로가 인증 없이 접근 가능 → 접근통제 미흡.
	//     차등 신호(anon==authed)만으로는 공개 페이지와 구분 불가하므로, 경로 의미로 판별한다.
	//     (인증 크롤링이 쿠키를 전역 주입해도 오탐 안 나도록 t.Auth 플래그에 의존하지 않음)
	if anonSeen && anon.ok && privilegedPath.MatchString(t.Path) {
		out = append(out, finding.Finding{
			Vuln: "인증 없이 접근 가능(접근통제 미흡)", Severity: "high", Host: t.Host, Path: t.Path, Method: "GET",
			Kind: "rule", Detector: "idor", Confidence: "medium",
			Evidence: fmt.Sprintf("특권 경로에 비인가(anon) 신원이 %d 로 접근됨", anon.status),
			Request:  reqLine("GET", urlOf(t)) + "  (신원: anon)",
			Response: fmt.Sprintf("anon 신원 응답 HTTP %d (특권 경로)", anon.status),
			RespCode: anon.status,
		})
	}

	// (2) 수평권한/IDOR: 서버가 세션을 강제(anon 은 거부)하는데도
	//     서로 다른 인증 신원이 동일 응답 → 객체 수준 인가(소유자 검증) 없음.
	//     anon 이 거부(비-2xx)여야 "인증은 되지만 소유자 무시" 신호가 분명해 공개 페이지 오탐을 배제.
	//     특권 경로는 수직 권한상승(privesc)이 담당하므로 여기선 제외(중복 방지).
	if len(named) >= 2 && anonSeen && !anon.ok && !privilegedPath.MatchString(t.Path) {
		same := true
		for _, r := range named[1:] {
			if r.hash != named[0].hash {
				same = false
				break
			}
		}
		if same {
			var names []string
			for _, r := range named {
				names = append(names, r.name)
			}
			out = append(out, finding.Finding{
				Vuln: "신원 간 동일 응답(수평권한/IDOR 후보)", Severity: "medium", Host: t.Host, Path: t.Path, Method: "GET",
				Kind: "rule", Detector: "idor", Confidence: "medium",
				Evidence: "세션 강제(anon 거부) 엔드포인트에서 신원 " + strings.Join(names, ", ") + " 이(가) 동일 응답 → 소유자 검증 미흡",
				Request:  reqLine("GET", urlOf(t)) + fmt.Sprintf("  (신원 %d개 교차)", len(named)),
				Response: fmt.Sprintf("anon 거부(%d), 신원 %s 응답 동일(해시 %s)", anon.status, strings.Join(names, ","), named[0].hash),
				RespCode: named[0].status,
			})
		}
	}
	return out
}

// ── 5) 수직 권한상승 (rule, 비파괴, FR-3.6) ──────────────────────
// 저권한 인증 신원이 "관리자 전용" 자원을 관리자와 동일하게 접근하면 수직 권한상승.
// 오탐 배제 게이트: (a) 특권 경로일 것, (b) anon 은 거부(세션 강제)될 것,
// (c) 관리자(고권한) 신원은 접근 성공할 것. 이 3조건 하에서만 저권한 접근을 위반으로 본다.
type verticalPrivEsc struct{}

func (verticalPrivEsc) ID() string        { return "privesc" }
func (verticalPrivEsc) Name() string      { return "수직 권한상승" }
func (verticalPrivEsc) Destructive() bool { return false }

func (verticalPrivEsc) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	ids := inj.Identities()
	var hasPriv, hasLow bool
	for _, id := range ids {
		if id.Name == "anon" {
			continue
		}
		if id.Privileged {
			hasPriv = true
		} else {
			hasLow = true
		}
	}
	if !hasPriv || !hasLow {
		return nil // 관리자·저권한 신원이 모두 있어야 대조 가능
	}
	if !privilegedPath.MatchString(t.Path) {
		return nil // (a) 특권 경로에 한함 (공유 자원 오탐 배제)
	}

	type res struct {
		name   string
		status int
		hash   string
		ok     bool
	}
	var anon res
	var anonSeen bool
	var admin *res
	var lows []res
	for _, id := range ids {
		resp, body, err := fetchAs(ctx, c, "GET", urlOf(t), id)
		if err != nil {
			continue
		}
		r := res{id.Name, resp.StatusCode, hash12(normalizeBody(body)), resp.StatusCode >= 200 && resp.StatusCode < 300}
		switch {
		case id.Name == "anon":
			anon, anonSeen = r, true
		case id.Privileged && r.ok && admin == nil:
			rr := r
			admin = &rr
		case !id.Privileged:
			lows = append(lows, r)
		}
	}
	// (b) anon 거부 + (c) 관리자 접근 성공.
	if !anonSeen || anon.ok || admin == nil {
		return nil
	}

	var out []finding.Finding
	for _, low := range lows {
		if low.ok && low.hash == admin.hash {
			out = append(out, finding.Finding{
				Vuln: "수직 권한상승(저권한이 관리자 자원 접근)", Severity: "high", Host: t.Host, Path: t.Path, Method: "GET",
				Kind: "rule", Detector: "privesc", Confidence: "medium",
				Evidence: fmt.Sprintf("저권한 신원 %s 가 관리자 %s 와 동일 응답 접근 (anon 은 %d 거부)", low.name, admin.name, anon.status),
				Request:  reqLine("GET", urlOf(t)) + fmt.Sprintf("  (신원: %s vs %s)", low.name, admin.name),
				Response: fmt.Sprintf("anon 거부(%d), 관리자 %s 와 저권한 %s 응답 동일(해시 %s)", anon.status, admin.name, low.name, admin.hash),
				RespCode: low.status,
			})
		}
	}
	return out
}

// injectQuery — 대상 파라미터 하나를 payload 로 덮어쓰되, 형제 쿼리 파라미터는
// 캡처된 샘플값으로 유지한 URL 문자열. (예: DVWA SQLi 는 Submit 파라미터가 있어야
// 취약 코드가 실행됨 → 한 파라미터만 보내면 놓친다.)
func injectQuery(t endpoints.Target, name, pl string) (string, bool) {
	u, err := url.Parse(urlOf(t))
	if err != nil {
		return "", false
	}
	q := u.Query()
	for _, p := range t.Params { // 형제 쿼리 파라미터 유지(트리거 플래그 등)
		if strings.Contains(p.In, "query") && p.Name != name {
			q.Set(p.Name, p.Sample)
		}
	}
	q.Set(name, pl)
	u.RawQuery = q.Encode()
	return u.String(), true
}

// probe — 파라미터에 페이로드를 주입한 요청 명세(쿼리·폼바디·JSON 공통). 능동 detector가 공유.
type probe struct {
	method, url, body, ctype string
}

// injectable — 능동 주입 대상 파라미터인가(쿼리·폼바디·JSON). cookie·file 은 제외.
func injectable(p endpoints.Param) bool {
	return strings.Contains(p.In, "query") || strings.Contains(p.In, "body") || strings.Contains(p.In, "json")
}

// bodyMethod — 바디 주입에 쓸 메서드. 캡처된 write 메서드(POST/PUT/PATCH) 우선, 없으면 POST.
func bodyMethod(t endpoints.Target) string {
	for _, m := range t.Methods {
		switch strings.ToUpper(m) {
		case "POST", "PUT", "PATCH":
			return strings.ToUpper(m)
		}
	}
	return "POST"
}

// buildProbe — 파라미터 tp 에 payload 를 주입한 요청 명세. 형제 파라미터는 Sample 로 보존한다.
// 쿼리는 URL, 폼바디는 x-www-form-urlencoded, JSON은 application/json 본문으로 주입.
func buildProbe(t endpoints.Target, tp endpoints.Param, payload string) (probe, bool) {
	switch {
	case strings.Contains(tp.In, "query"):
		u, ok := injectQuery(t, tp.Name, payload)
		if !ok {
			return probe{}, false
		}
		return probe{method: "GET", url: u}, true
	case strings.Contains(tp.In, "json"):
		// 중첩 구조를 dot-path 로 재구성(형제 leaf 는 Sample, 대상은 payload). 배열 인덱스 지원.
		var root any
		for _, p := range t.Params {
			if !strings.Contains(p.In, "json") {
				continue
			}
			v := p.Sample
			if p.Name == tp.Name {
				v = payload
			}
			root = insertJSONPath(root, strings.Split(p.Name, "."), v)
		}
		b, err := json.Marshal(root)
		if err != nil {
			return probe{}, false
		}
		return probe{method: bodyMethod(t), url: urlOf(t), body: string(b), ctype: "application/json"}, true
	case strings.Contains(tp.In, "body"):
		form := url.Values{}
		for _, p := range t.Params {
			if strings.Contains(p.In, "body") && p.Name != tp.Name && p.Sample != "" {
				form.Set(p.Name, p.Sample) // 형제 폼 필드 보존(트리거 플래그 등)
			}
		}
		form.Set(tp.Name, payload)
		return probe{method: bodyMethod(t), url: urlOf(t), body: form.Encode(), ctype: "application/x-www-form-urlencoded"}, true
	}
	return probe{}, false
}

// insertJSONPath — dot-path segs 위치에 val 을 넣어 중첩 구조(map/slice)를 누적 재구성한다.
// 세그먼트가 숫자면 배열 인덱스, 아니면 객체 키. 기존 노드는 보존하며 확장한다(형제 leaf 누적).
func insertJSONPath(node any, segs []string, val any) any {
	if len(segs) == 0 {
		return val
	}
	seg := segs[0]
	if idx, err := strconv.Atoi(seg); err == nil { // 배열 인덱스
		arr, _ := node.([]any)
		for len(arr) <= idx {
			arr = append(arr, nil)
		}
		arr[idx] = insertJSONPath(arr[idx], segs[1:], val)
		return arr
	}
	m, _ := node.(map[string]any) // 객체 키
	if m == nil {
		m = map[string]any{}
	}
	m[seg] = insertJSONPath(m[seg], segs[1:], val)
	return m
}

// newProbeReq — probe 명세로 *http.Request 생성(인증 주입 전).
func newProbeReq(ctx context.Context, pr probe) (*http.Request, error) {
	var r io.Reader
	if pr.body != "" {
		r = strings.NewReader(pr.body)
	}
	req, err := http.NewRequestWithContext(ctx, pr.method, pr.url, r)
	if err != nil {
		return nil, err
	}
	if pr.ctype != "" {
		req.Header.Set("Content-Type", pr.ctype)
	}
	return req, nil
}

// fetchProbe — probe 요청 실행(rate limit + 인증 주입), 응답+본문 반환. 세션 만료 시 자동 재로그인·재시도.
func fetchProbe(ctx context.Context, c *http.Client, inj *auth.Injector, pr probe) (*http.Response, string, error) {
	return doInjected(ctx, c, inj, pr)
}

// fetchTimedProbe — probe 왕복 시간 측정(본문 버림). 시간 기반 판정용.
func fetchTimedProbe(ctx context.Context, c *http.Client, inj *auth.Injector, pr probe) (time.Duration, error) {
	throttle()
	req, err := newProbeReq(ctx, pr)
	if err != nil {
		return 0, err
	}
	inj.Inject(req)
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return time.Since(start), nil
}

// fetchProbeNoRedirect — probe 를 리다이렉트 미추적으로 실행(오픈 리다이렉트 Location 확인). 호출자가 Body 닫음.
func fetchProbeNoRedirect(ctx context.Context, c *http.Client, inj *auth.Injector, pr probe) (*http.Response, error) {
	throttle()
	req, err := newProbeReq(ctx, pr)
	if err != nil {
		return nil, err
	}
	inj.Inject(req)
	nf := *c
	nf.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return nf.Do(req)
}

// probeLine — 증적용 재현 요청 라인(마스킹). 바디가 있으면 함께 표기.
func probeLine(pr probe) string {
	line := reqLine(pr.method, pr.url)
	if pr.body != "" {
		line += " | body: " + masking.Mask(pr.body)
	}
	return line
}

// ── 6) SQL 주입 (에러 기반, rule, 비파괴) ─────────────────────────
type sqlInjection struct{}

func (sqlInjection) ID() string        { return "sqli" }
func (sqlInjection) Name() string      { return "SQL 주입(에러 기반)" }
func (sqlInjection) Destructive() bool { return false }

func (sqlInjection) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	for _, p := range t.Params {
		if !injectable(p) {
			continue
		}
		for _, pl := range payload.SQLi() {
			pr, ok := buildProbe(t, p, pl)
			if !ok {
				continue
			}
			resp, body, err := fetchProbe(ctx, c, inj, pr)
			if err != nil {
				continue
			}
			if dbms, m := payload.FindSQLError(body); dbms != "" {
				out = append(out, finding.Finding{
					Vuln: "SQL 주입(에러 기반)", Severity: "high", Host: t.Host, Path: t.Path, Method: pr.method,
					Param: p.Name, Kind: "rule", Detector: "sqli", Confidence: "high",
					Evidence:    "파라미터 " + p.Name + "(" + p.In + ") 주입 시 " + dbms + " DB 오류 메시지 노출",
					Request:     probeLine(pr),
					Response:    snippet(body, m),
					RespCode:    resp.StatusCode,
					ContentType: ctype(resp),
				})
				break // 파라미터당 1건
			}
		}
	}
	return out
}

// ── 6b) 블라인드 SQL 주입 (불린 기반, rule, 비파괴) ───────────────
// 에러를 숨기는 대상용: 참/거짓 조건의 응답 차이로 주입 여부 판정.
// 참(AND 1=1)≈원본, 거짓(AND 1=2)≠원본 이면 주입이 쿼리 결과에 반영된 것.
type blindSQLi struct{}

func (blindSQLi) ID() string        { return "sqli-blind" }
func (blindSQLi) Name() string      { return "SQL 주입(블라인드/불린 기반)" }
func (blindSQLi) Destructive() bool { return false }

func (blindSQLi) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	for _, p := range t.Params {
		if !injectable(p) {
			continue
		}
		base := p.Sample
		if base == "" {
			base = "1"
		}
		// 원본값 응답(기준선).
		basePr, ok := buildProbe(t, p, base)
		if !ok {
			continue
		}
		_, baseBody, err := fetchProbe(ctx, c, inj, basePr)
		if err != nil {
			continue
		}
		for _, pair := range payload.SQLiBlindPairs() {
			tPr, ok1 := buildProbe(t, p, base+pair[0]) // 참
			fPr, ok2 := buildProbe(t, p, base+pair[1]) // 거짓
			if !ok1 || !ok2 {
				continue
			}
			_, tBody, err1 := fetchProbe(ctx, c, inj, tPr)
			_, fBody, err2 := fetchProbe(ctx, c, inj, fPr)
			if err1 != nil || err2 != nil {
				continue
			}
			// 동적 콘텐츠(토큰·시각) 제거 후 비교 → CSRF 토큰 등으로 길이가 흔들려 생기는 오탐 배제.
			nBase, nT, nF := normalizeBody(baseBody), normalizeBody(tBody), normalizeBody(fBody)
			// 참≈원본 && 참≠거짓 → 불린 조건이 쿼리 결과를 바꿈 = 주입 가능.
			if similarLen(nT, nBase) && !similarLen(nT, nF) {
				out = append(out, finding.Finding{
					Vuln: "SQL 주입(블라인드/불린 기반)", Severity: "high", Host: t.Host, Path: t.Path, Method: tPr.method,
					Param: p.Name, Kind: "rule", Detector: "sqli-blind", Confidence: "medium",
					Evidence: fmt.Sprintf("파라미터 %s(%s): 참(%s)·거짓(%s) 조건에 응답이 갈림 → 블라인드 주입", p.Name, p.In, pair[0], pair[1]),
					Request:  probeLine(tPr) + "  vs  " + masking.Mask(fPr.body+fPr.url),
					Response: fmt.Sprintf("참 응답 %dB(원본과 유사), 거짓 응답 %dB(상이)", len(tBody), len(fBody)),
				})
				break // 파라미터당 1건
			}
		}
	}
	return out
}

// ── 6c) 시간 기반 블라인드 SQL 주입 (rule, 비파괴) ────────────────
// 응답 내용 차이가 전혀 없는 완전 블라인드용: 지연 페이로드(SLEEP 등)로 응답을 늦춘 뒤
// 무지연 대비 시간 차이로 판정. 자연적으로 느린 엔드포인트는 지연/무지연 모두 느려 차등이 작아 배제.
type timeBlindSQLi struct{}

func (timeBlindSQLi) ID() string        { return "sqli-time" }
func (timeBlindSQLi) Name() string      { return "SQL 주입(시간 기반 블라인드)" }
func (timeBlindSQLi) Destructive() bool { return false }

func (timeBlindSQLi) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	delay := time.Duration(payload.SQLiTimeDelay) * time.Second
	thresh := delay * 3 / 5 // 지연의 60% (예: 3s → 1.8s)
	for _, p := range t.Params {
		if !injectable(p) {
			continue
		}
		base := p.Sample
		if base == "" {
			base = "1"
		}
		for _, pair := range payload.SQLiTimePairs() {
			slowPr, ok1 := buildProbe(t, p, base+pair[0])
			fastPr, ok2 := buildProbe(t, p, base+pair[1])
			if !ok1 || !ok2 {
				continue
			}
			// 1차 측정 — 지연 페이로드가 delay 만큼 느리고 무지연 대비 차이가 명확한가.
			slow1, fast1, ok := timedPair(ctx, c, inj, slowPr, fastPr, thresh)
			if !ok {
				continue
			}
			// 확증(정밀도 2차) — 네트워크 지터로 인한 단발성 오탐 배제: 2차 측정도 통과해야 인정.
			slow2, fast2, ok := timedPair(ctx, c, inj, slowPr, fastPr, thresh)
			if !ok {
				continue
			}
			out = append(out, finding.Finding{
				Vuln: "SQL 주입(시간 기반 블라인드)", Severity: "high", Host: t.Host, Path: t.Path, Method: slowPr.method,
				Param: p.Name, Kind: "rule", Detector: "sqli-time", Confidence: "high", // 2회 확증 → high
				Evidence: fmt.Sprintf("파라미터 %s(%s): 지연 응답 2회 확증 %.1fs·%.1fs vs 무지연 %.1fs·%.1fs → 시간 기반 주입", p.Name, p.In, slow1.Seconds(), slow2.Seconds(), fast1.Seconds(), fast2.Seconds()),
				Request:  probeLine(slowPr),
				Response: fmt.Sprintf("지연 %.1fs/%.1fs · 무지연 %.1fs/%.1fs (2회 확증, 응답 내용 동일·시간 차만)", slow1.Seconds(), slow2.Seconds(), fast1.Seconds(), fast2.Seconds()),
			})
			break // 파라미터당 1건
		}
	}
	return out
}

// timedPair — 무지연/지연 probe 응답시간을 재고 시간 기반 주입 조건 충족 여부를 반환.
// 매 호출마다 대조(무지연)를 새로 재 자연적으로 느린 엔드포인트의 순간 부하를 함께 반영한다.
func timedPair(ctx context.Context, c *http.Client, inj *auth.Injector, slowPr, fastPr probe, thresh time.Duration) (slow, fast time.Duration, ok bool) {
	fast, e1 := fetchTimedProbe(ctx, c, inj, fastPr) // 무지연(대조)
	slow, e2 := fetchTimedProbe(ctx, c, inj, slowPr) // 지연
	if e1 != nil || e2 != nil {
		return 0, 0, false
	}
	return slow, fast, slow >= thresh && slow-fast >= thresh
}

// similarLen — 두 응답이 길이 기준 유사한가(동적 콘텐츠 오차 허용). 20바이트 또는 5% 이내.
func similarLen(a, b string) bool {
	la, lb := len(a), len(b)
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	max := la
	if lb > max {
		max = lb
	}
	return diff <= 20 || diff*100/(max+1) <= 5
}

// ── 7) 경로 순회 (rule, 비파괴 — 읽기) ────────────────────────────
type pathTraversal struct{}

func (pathTraversal) ID() string        { return "path-traversal" }
func (pathTraversal) Name() string      { return "경로 순회(Path Traversal)" }
func (pathTraversal) Destructive() bool { return false }

func (pathTraversal) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	for _, p := range t.Params {
		if !injectable(p) {
			continue
		}
		for _, pl := range payload.Traversal() {
			pr, ok := buildProbe(t, p, pl)
			if !ok {
				continue
			}
			resp, body, err := fetchProbe(ctx, c, inj, pr)
			if err != nil {
				continue
			}
			if file, m := payload.FindTraversal(body); file != "" {
				out = append(out, finding.Finding{
					Vuln: "경로 순회(Path Traversal)", Severity: "high", Host: t.Host, Path: t.Path, Method: pr.method,
					Param: p.Name, Kind: "rule", Detector: "path-traversal", Confidence: "high",
					Evidence:    "파라미터 " + p.Name + "(" + p.In + ") 경로순회 주입 시 " + file + " 내용 노출",
					Request:     probeLine(pr),
					Response:    snippet(body, m),
					RespCode:    resp.StatusCode,
					ContentType: ctype(resp),
				})
				break
			}
		}
	}
	return out
}

// ── 8) 오픈 리다이렉트 (rule, 비파괴) ─────────────────────────────
type openRedirect struct{}

// 리다이렉트 목적지로 흔히 쓰이는 파라미터명.
var redirectParam = regexp.MustCompile(`(?i)^(redirect(_?url)?|url|uri|next|return(_?url|to)?|dest(ination)?|target|goto|continue|forward|out|link|r|u)$`)

// 주입 마커 호스트 — 응답의 Location 이 이 호스트를 가리키면 오픈 리다이렉트 확정.
const redirectMarker = "evil.zqxj9.example"

func (openRedirect) ID() string        { return "open-redirect" }
func (openRedirect) Name() string      { return "오픈 리다이렉트" }
func (openRedirect) Destructive() bool { return false }

func (openRedirect) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	for _, p := range t.Params {
		if !injectable(p) || !redirectParam.MatchString(p.Name) {
			continue
		}
		pr, ok := buildProbe(t, p, "https://"+redirectMarker+"/")
		if !ok {
			continue
		}
		resp, err := fetchProbeNoRedirect(ctx, c, inj, pr)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			if lu, err := url.Parse(loc); err == nil && strings.EqualFold(lu.Hostname(), redirectMarker) {
				out = append(out, finding.Finding{
					Vuln: "오픈 리다이렉트", Severity: "medium", Host: t.Host, Path: t.Path, Method: pr.method,
					Param: p.Name, Kind: "rule", Detector: "open-redirect", Confidence: "high",
					Evidence:    "파라미터 " + p.Name + "(" + p.In + ") 로 외부 호스트(" + redirectMarker + ") 리다이렉트됨",
					Request:     probeLine(pr),
					Response:    fmt.Sprintf("HTTP %d  Location: %s", resp.StatusCode, masking.Mask(loc)),
					RespCode:    resp.StatusCode,
					ContentType: ctype(resp),
				})
			}
		}
	}
	return out
}

// ── 8b) OS 커맨드 인젝션 (rule, 비파괴 — 무해 명령) ───────────────
// 출력 기반: id/whoami/ver 를 셸 분리자로 이어붙여 출력 노출을 확인.
// 출력이 안 나오면 시간 기반(블라인드): sleep/ping 지연을 2회 확증(지터 오탐 배제).
type cmdInjection struct{}

func (cmdInjection) ID() string        { return "cmd-injection" }
func (cmdInjection) Name() string      { return "OS 커맨드 인젝션" }
func (cmdInjection) Destructive() bool { return false } // 페이로드는 무해(id·sleep·ver)

func (cmdInjection) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	delay := time.Duration(payload.CmdTimeDelay) * time.Second
	thresh := delay * 3 / 5
	for _, p := range t.Params {
		if !injectable(p) {
			continue
		}
		base := p.Sample
		// (1) 출력 기반 — 명령 출력이 응답에 노출되는가.
		hit := false
		for _, pl := range payload.CmdInjection() {
			pr, ok := buildProbe(t, p, base+pl)
			if !ok {
				continue
			}
			resp, body, err := fetchProbe(ctx, c, inj, pr)
			if err != nil {
				continue
			}
			if name, m := payload.FindCmdOutput(body); name != "" {
				out = append(out, finding.Finding{
					Vuln: "OS 커맨드 인젝션", Severity: "high", Host: t.Host, Path: t.Path, Method: pr.method,
					Param: p.Name, Kind: "rule", Detector: "cmd-injection", Confidence: "high",
					Evidence:    "파라미터 " + p.Name + "(" + p.In + ") 주입 시 명령 출력 노출(" + name + ")",
					Request:     probeLine(pr),
					Response:    snippet(body, m),
					RespCode:    resp.StatusCode,
					ContentType: ctype(resp),
				})
				hit = true
				break
			}
		}
		if hit {
			continue
		}
		// (2) 시간 기반(블라인드) — 지연 명령이 응답을 늦추는가. 2회 확증.
		bt := base
		if bt == "" {
			bt = "1"
		}
		for _, pair := range payload.CmdInjectionTimePairs() {
			slowPr, ok1 := buildProbe(t, p, bt+pair[0])
			fastPr, ok2 := buildProbe(t, p, bt+pair[1])
			if !ok1 || !ok2 {
				continue
			}
			slow1, fast1, ok := timedPair(ctx, c, inj, slowPr, fastPr, thresh)
			if !ok {
				continue
			}
			slow2, _, ok := timedPair(ctx, c, inj, slowPr, fastPr, thresh)
			if !ok {
				continue
			}
			out = append(out, finding.Finding{
				Vuln: "OS 커맨드 인젝션(블라인드)", Severity: "high", Host: t.Host, Path: t.Path, Method: slowPr.method,
				Param: p.Name, Kind: "rule", Detector: "cmd-injection", Confidence: "high",
				Evidence: fmt.Sprintf("파라미터 %s(%s): 지연 명령 2회 확증 %.1fs·%.1fs vs 무지연 %.1fs → 블라인드 커맨드 인젝션", p.Name, p.In, slow1.Seconds(), slow2.Seconds(), fast1.Seconds()),
				Request:  probeLine(slowPr),
				Response: fmt.Sprintf("지연 %.1fs/%.1fs · 무지연 %.1fs (2회 확증)", slow1.Seconds(), slow2.Seconds(), fast1.Seconds()),
			})
			break
		}
	}
	return out
}

// ── 8c) SSRF 서버측 요청 위조 (rule, 비파괴) ──────────────────────
// url류 파라미터에 내부/메타데이터/파일 스킴을 주입해, 서버가 대신 요청한 내용이
// 응답에 노출되는지(메타데이터·/etc/passwd 시그니처)로 판정. OOB 없이 in-band 신호만.
type ssrf struct{}

// SSRF 주입 대상이 되는 URL 성격의 파라미터명.
var ssrfParam = regexp.MustCompile(`(?i)^(url|uri|link|src|href|dest(ination)?|redirect|next|target|to|out|load|fetch|feed|rss|proxy|callback|webhook|image|img|avatar|file|path|domain|host|site|page|data|ref(erence)?|resource|remote|source|endpoint)$`)

func (ssrf) ID() string        { return "ssrf" }
func (ssrf) Name() string      { return "서버측 요청 위조(SSRF)" }
func (ssrf) Destructive() bool { return false }

func (ssrf) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	for _, p := range t.Params {
		if !injectable(p) || !ssrfParam.MatchString(p.Name) {
			continue
		}
		for _, pl := range payload.SSRF() {
			pr, ok := buildProbe(t, p, pl)
			if !ok {
				continue
			}
			resp, body, err := fetchProbe(ctx, c, inj, pr)
			if err != nil {
				continue
			}
			if name, m := payload.FindSSRF(body); name != "" {
				out = append(out, finding.Finding{
					Vuln: "서버측 요청 위조(SSRF)", Severity: "high", Host: t.Host, Path: t.Path, Method: pr.method,
					Param: p.Name, Kind: "rule", Detector: "ssrf", Confidence: "high",
					Evidence:    "파라미터 " + p.Name + "(" + p.In + ") 로 내부 자원 요청 성공(" + name + ")",
					Request:     probeLine(pr),
					Response:    snippet(body, m),
					RespCode:    resp.StatusCode,
					ContentType: ctype(resp),
				})
				break // 파라미터당 1건
			}
		}
	}
	return out
}

// ── 8d) SSTI 서버측 템플릿 인젝션 (rule, 비파괴) ──────────────────
// 산술식을 주입해 서버 템플릿이 평가하면 고유 결과값이 나타남. 원본 식이 그대로 반사되면(미평가) 제외.
type ssti struct{}

func (ssti) ID() string        { return "ssti" }
func (ssti) Name() string      { return "서버측 템플릿 인젝션(SSTI)" }
func (ssti) Destructive() bool { return false }

func (ssti) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	for _, p := range t.Params {
		if !injectable(p) {
			continue
		}
		for _, pl := range payload.SSTIPayloads() {
			pr, ok := buildProbe(t, p, pl)
			if !ok {
				continue
			}
			resp, body, err := fetchProbe(ctx, c, inj, pr)
			if err != nil {
				continue
			}
			// 평가 결과값이 나오고 원본 식은 안 보이면 템플릿이 실제로 평가한 것 = SSTI.
			if strings.Contains(body, payload.SSTIResult) && !strings.Contains(body, pl) {
				out = append(out, finding.Finding{
					Vuln: "서버측 템플릿 인젝션(SSTI)", Severity: "high", Host: t.Host, Path: t.Path, Method: pr.method,
					Param: p.Name, Kind: "rule", Detector: "ssti", Confidence: "high",
					Evidence:    "파라미터 " + p.Name + "(" + p.In + ") 의 템플릿 식이 서버에서 평가됨(결과값 " + payload.SSTIResult + " 노출)",
					Request:     probeLine(pr),
					Response:    snippet(body, payload.SSTIResult),
					RespCode:    resp.StatusCode,
					ContentType: ctype(resp),
				})
				break // 파라미터당 1건
			}
		}
	}
	return out
}

// ── 8e) XXE XML 외부객체 공격 (rule, 비파괴 — 읽기) ────────────────
// XML을 처리하는 엔드포인트에 외부 엔티티(file:///etc/passwd)를 포함한 XML을 보내 파일 내용 노출 여부 확인.
type xxe struct{}

func (xxe) ID() string        { return "xxe" }
func (xxe) Name() string      { return "XML 외부객체 공격(XXE)" }
func (xxe) Destructive() bool { return false }

func (xxe) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	method := bodyMethod(t) // XML 본문 전송(POST/PUT/PATCH)
	for _, pl := range payload.XXEPayloads() {
		pr := probe{method: method, url: urlOf(t), body: pl, ctype: "application/xml"}
		resp, body, err := fetchProbe(ctx, c, inj, pr)
		if err != nil {
			continue
		}
		if file, m := payload.FindTraversal(body); file != "" { // passwd·win.ini 시그니처 재사용
			out = append(out, finding.Finding{
				Vuln: "XML 외부객체 공격(XXE)", Severity: "high", Host: t.Host, Path: t.Path, Method: method,
				Kind: "rule", Detector: "xxe", Confidence: "high",
				Evidence:    "외부 엔티티로 " + file + " 내용이 응답에 노출됨(XML 파서 XXE 취약)",
				Request:     probeLine(pr),
				Response:    snippet(body, m),
				RespCode:    resp.StatusCode,
				ContentType: ctype(resp),
			})
			break
		}
	}
	return out
}

// ── 8f) LDAP 인젝션 (rule, 비파괴 — 에러 기반) ────────────────────
// LDAP 필터를 깨는 특수문자를 주입해 LDAP 파서/JNDI 오류가 노출되는지로 판정.
type ldapInjection struct{}

func (ldapInjection) ID() string        { return "ldap-injection" }
func (ldapInjection) Name() string      { return "LDAP 인젝션" }
func (ldapInjection) Destructive() bool { return false }

func (ldapInjection) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	for _, p := range t.Params {
		if !injectable(p) {
			continue
		}
		for _, pl := range payload.LDAP() {
			pr, ok := buildProbe(t, p, pl)
			if !ok {
				continue
			}
			resp, body, err := fetchProbe(ctx, c, inj, pr)
			if err != nil {
				continue
			}
			if name, m := payload.FindLDAPError(body); name != "" {
				out = append(out, finding.Finding{
					Vuln: "LDAP 인젝션", Severity: "high", Host: t.Host, Path: t.Path, Method: pr.method,
					Param: p.Name, Kind: "rule", Detector: "ldap-injection", Confidence: "high",
					Evidence:    "파라미터 " + p.Name + "(" + p.In + ") 주입 시 LDAP 오류 노출",
					Request:     probeLine(pr),
					Response:    snippet(body, m),
					RespCode:    resp.StatusCode,
					ContentType: ctype(resp),
				})
				break // 파라미터당 1건
			}
		}
	}
	return out
}

// ── 8g) SSI 인젝션 (rule, 비파괴) ─────────────────────────────────
// SSI 지시자(#exec echo)를 주입해 서버가 실행하면 고유 마커가 출력됨. 원본 지시자 반사(미실행)면 제외.
type ssiInjection struct{}

func (ssiInjection) ID() string        { return "ssi-injection" }
func (ssiInjection) Name() string      { return "SSI 인젝션" }
func (ssiInjection) Destructive() bool { return false }

func (ssiInjection) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	var out []finding.Finding
	for _, p := range t.Params {
		if !injectable(p) {
			continue
		}
		for _, pl := range payload.SSIPayloads() {
			pr, ok := buildProbe(t, p, pl)
			if !ok {
				continue
			}
			resp, body, err := fetchProbe(ctx, c, inj, pr)
			if err != nil {
				continue
			}
			// 마커가 나오고 원본 지시자는 안 보이면 SSI가 실제로 실행된 것.
			if strings.Contains(body, payload.SSIMarker) && !strings.Contains(body, pl) {
				out = append(out, finding.Finding{
					Vuln: "SSI 인젝션", Severity: "high", Host: t.Host, Path: t.Path, Method: pr.method,
					Param: p.Name, Kind: "rule", Detector: "ssi-injection", Confidence: "high",
					Evidence:    "파라미터 " + p.Name + "(" + p.In + ") 의 SSI 지시자가 서버에서 실행됨(마커 " + payload.SSIMarker + " 출력)",
					Request:     probeLine(pr),
					Response:    snippet(body, payload.SSIMarker),
					RespCode:    resp.StatusCode,
					ContentType: ctype(resp),
				})
				break // 파라미터당 1건
			}
		}
	}
	return out
}

// ── 9) CSRF 토큰 부재 (rule, 비파괴 — 수동적 분석) ────────────────
// 상태변경(POST/PUT/PATCH/DELETE) + 세션(쿠키) 인증 요청인데 anti-CSRF 토큰이 없으면 후보.
// 능동 재현(토큰 없이 상태변경 재전송)은 파괴적이라 기본 제외 → 토큰 부재만 판정(HITL 검토).
// SameSite 쿠키로 완화될 수 있어 confidence=low.
type csrfMissing struct{}

// anti-CSRF 토큰으로 흔히 쓰이는 파라미터/헤더 이름.
var csrfTokenName = regexp.MustCompile(`(?i)(csrf|xsrf|_token|authenticity_token|__requestverificationtoken|user_token|nonce|anticsrf)`)

func (csrfMissing) ID() string        { return "csrf" }
func (csrfMissing) Name() string      { return "CSRF 토큰 부재" }
func (csrfMissing) Destructive() bool { return false }

func (csrfMissing) Detect(ctx context.Context, t endpoints.Target, c *http.Client, _ *auth.Injector) []finding.Finding {
	method := writeMethod(t.Methods)
	if method == "" {
		return nil // 상태변경 요청만 대상
	}
	if !t.Auth {
		return nil // 세션 인증 요청만 — CSRF는 인증된 사용자 문맥을 악용
	}
	for _, p := range t.Params {
		if csrfTokenName.MatchString(p.Name) {
			return nil // anti-CSRF 토큰 존재 → 보호됨
		}
	}
	return []finding.Finding{{
		Vuln: "CSRF 토큰 부재", Severity: "medium", Host: t.Host, Path: t.Path, Method: method,
		Kind: "rule", Detector: "csrf", Confidence: "low",
		Evidence: "상태변경(" + method + ") + 세션 인증 요청에 anti-CSRF 토큰 없음",
		Request:  method + " " + masking.Mask(urlOf(t)),
		Response: "요청 파라미터에 CSRF 토큰(csrf/_token/nonce 등) 부재 — SameSite 쿠키 여부 수동 확인 필요",
	}}
}

// writeMethod — 메서드 목록 중 첫 상태변경 메서드("" = 없음).
func writeMethod(methods []string) string {
	for _, m := range methods {
		switch strings.ToUpper(m) {
		case "POST", "PUT", "PATCH", "DELETE":
			return strings.ToUpper(m)
		}
	}
	return ""
}

// ── 10) 파일 업로드 제한 미흡 (rule, 파괴적=대상에 파일 생성 → opt-in) ──
// 무해한 마커 파일을 위험 확장자(.php)로 업로드해 서버가 거부하는지 확인.
// 수용되면 확장자 검증 부재 후보. 대상에 파일을 쓰므로 AllowDestructive 옵트인 필요.
type fileUpload struct{}

const (
	uploadName    = "zqxj9_test.php"    // 위험 확장자(실행 코드는 없음)
	uploadContent = "ZQXJ9-UPLOAD-TEST" // 무해한 마커
)

func (fileUpload) ID() string        { return "file-upload" }
func (fileUpload) Name() string      { return "파일 업로드 제한 미흡" }
func (fileUpload) Destructive() bool { return true }

func (fileUpload) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	if writeMethod(t.Methods) == "" {
		return nil
	}
	var out []finding.Finding
	for _, p := range t.Params {
		if !strings.Contains(p.In, "file") { // 파일 업로드 필드가 있는 엔드포인트만
			continue
		}
		fields := map[string]string{} // 함께 온 일반 필드는 샘플값으로 채움
		for _, q := range t.Params {
			if q.Name != p.Name && strings.Contains(q.In, "body") {
				fields[q.Name] = q.Sample
			}
		}
		resp, body, err := fetchUpload(ctx, c, inj, urlOf(t), p.Name, fields)
		if err != nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 { // 수용됨 → 확장자 검증 미흡
			out = append(out, finding.Finding{
				Vuln: "파일 업로드 제한 미흡", Severity: "high", Host: t.Host, Path: t.Path, Method: "POST",
				Param: p.Name, Kind: "rule", Detector: "file-upload", Confidence: "medium",
				Evidence:    "위험 확장자(.php) 파일이 거부 없이 업로드 수용됨",
				Request:     "POST " + masking.Mask(urlOf(t)) + " (multipart " + p.Name + "=" + uploadName + ")",
				Response:    fmt.Sprintf("HTTP %d — %s", resp.StatusCode, snippet(body, "")),
				RespCode:    resp.StatusCode,
				ContentType: ctype(resp),
			})
			break // 엔드포인트당 1건
		}
	}
	return out
}

// fetchUpload — 위험 확장자 마커 파일을 multipart 로 업로드(인증 주입). 호출자 rate-limit 후.
func fetchUpload(ctx context.Context, c *http.Client, inj *auth.Injector, rawURL, fileField string, fields map[string]string) (*http.Response, string, error) {
	throttle()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	fw, err := mw.CreateFormFile(fileField, uploadName)
	if err != nil {
		return nil, "", err
	}
	_, _ = fw.Write([]byte(uploadContent))
	_ = mw.Close()

	req, err := http.NewRequestWithContext(ctx, "POST", rawURL, &buf)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	inj.Inject(req)
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(b), nil
}

// ── 11) 쿠키 보안속성 미흡 (CC, rule, 비파괴 — 수동적) ────────────
// Set-Cookie 에 HttpOnly/Secure/SameSite 가 없으면 탈취·변조에 취약(KII 웹 CC 쿠키 변조).
type cookieSecurity struct{}

func (cookieSecurity) ID() string        { return "cookie-security" }
func (cookieSecurity) Name() string      { return "쿠키 보안속성 미흡" }
func (cookieSecurity) Destructive() bool { return false }

func (cookieSecurity) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	resp, _, err := fetch(ctx, c, inj, "GET", urlOf(t))
	if err != nil {
		return nil
	}
	var out []finding.Finding
	for _, ck := range resp.Cookies() {
		var missing []string
		if !ck.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if !ck.Secure {
			missing = append(missing, "Secure")
		}
		if ck.SameSite == http.SameSiteNoneMode { // 명시적 None 만(미설정은 브라우저 Lax 기본 → 노이즈 제외)
			missing = append(missing, "SameSite=None")
		}
		if len(missing) == 0 {
			continue
		}
		out = append(out, finding.Finding{
			Vuln: "쿠키 보안속성 미흡", Severity: "medium", Host: t.Host, Path: t.Path, Method: "GET",
			Param: ck.Name, Kind: "rule", Detector: "cookie-security", Confidence: "high",
			Evidence:    "쿠키 " + ck.Name + " 보안속성 누락: " + strings.Join(missing, ", "),
			Request:     reqLine("GET", urlOf(t)),
			Response:    "Set-Cookie: " + ck.Name + " (누락: " + strings.Join(missing, ", ") + ")",
			RespCode:    resp.StatusCode,
			ContentType: ctype(resp),
		})
	}
	return out
}

// ── 12) 위험 HTTP 메소드 허용 (WM, rule, 비파괴 — OPTIONS 조회) ────
// OPTIONS 응답의 Allow 헤더에 PUT/DELETE/TRACE 등 위험 메소드가 있으면 후보(KII 웹 WM).
type httpMethod struct{}

var dangerousMethods = []string{"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

func (httpMethod) ID() string        { return "http-method" }
func (httpMethod) Name() string      { return "위험 HTTP 메소드 허용" }
func (httpMethod) Destructive() bool { return false }

func (httpMethod) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	resp, _, err := fetch(ctx, c, inj, "OPTIONS", urlOf(t))
	if err != nil {
		return nil
	}
	allow := strings.ToUpper(resp.Header.Get("Allow"))
	if allow == "" {
		return nil
	}
	var found []string
	for _, m := range dangerousMethods {
		if strings.Contains(allow, m) {
			found = append(found, m)
		}
	}
	if len(found) == 0 {
		return nil
	}
	return []finding.Finding{{
		Vuln: "위험 HTTP 메소드 허용", Severity: "medium", Host: t.Host, Path: t.Path, Method: "OPTIONS",
		Kind: "rule", Detector: "http-method", Confidence: "high",
		Evidence:    "허용 메소드에 위험 메소드 포함: " + strings.Join(found, ", "),
		Request:     reqLine("OPTIONS", urlOf(t)),
		Response:    "Allow: " + resp.Header.Get("Allow"),
		RespCode:    resp.StatusCode,
		ContentType: ctype(resp),
	}}
}

// ── 13) 디렉터리 인덱싱 (DI, rule, 비파괴) ─────────────────────────
// 상위 디렉터리 요청 시 파일 목록이 노출되면 디렉터리 인덱싱(KII 웹 DI).
type dirIndexing struct{}

// 서버별 디렉터리 목록 시그니처.
var dirListingSig = regexp.MustCompile(`(?i)<title>Index of /|Index of /[^<]*</h1>|Directory listing for|\[To Parent Directory\]`)

func (dirIndexing) ID() string        { return "dir-indexing" }
func (dirIndexing) Name() string      { return "디렉터리 인덱싱" }
func (dirIndexing) Destructive() bool { return false }

func (dirIndexing) Detect(ctx context.Context, t endpoints.Target, c *http.Client, inj *auth.Injector) []finding.Finding {
	dir := parentDir(t.Path)
	if dir == "" {
		return nil
	}
	scheme := t.Scheme
	if scheme == "" {
		scheme = "https"
	}
	resp, body, err := fetch(ctx, c, inj, "GET", scheme+"://"+t.Host+dir)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	if m := dirListingSig.FindString(body); m != "" {
		return []finding.Finding{{
			Vuln: "디렉터리 인덱싱", Severity: "medium", Host: t.Host, Path: dir, Method: "GET",
			Kind: "rule", Detector: "dir-indexing", Confidence: "high",
			Evidence:    "디렉터리 " + dir + " 에서 파일 목록 노출",
			Request:     reqLine("GET", scheme+"://"+t.Host+dir),
			Response:    snippet(body, m),
			RespCode:    resp.StatusCode,
			ContentType: ctype(resp),
		}}
	}
	return nil
}

// parentDir — 경로의 상위 디렉터리("/a/b/c" → "/a/b/"). 루트/빈 경로면 "".
func parentDir(p string) string {
	p = strings.TrimRight(p, "/")
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return ""
	}
	return p[:i+1]
}

// ── 14) 파괴적 데모 (기본 제외, 가드레일 FR-3.2 시연) ─────────────
type destructiveDemo struct{}

func (destructiveDemo) ID() string        { return "destructive-demo" }
func (destructiveDemo) Name() string      { return "(데모) 파괴적 점검" }
func (destructiveDemo) Destructive() bool { return true }

func (destructiveDemo) Detect(ctx context.Context, t endpoints.Target, c *http.Client, _ *auth.Injector) []finding.Finding {
	// AllowDestructive=true 로 옵트인했을 때만 실행됨을 보여주는 데모.
	return []finding.Finding{{
		Vuln: "(데모) 파괴적 점검 실행됨", Severity: "info", Host: t.Host, Path: t.Path, Method: "GET",
		Kind: "rule", Detector: "destructive-demo", Confidence: "low",
		Evidence: "AllowDestructive 옵트인으로 실행 (실제 파괴적 로직 없음)",
	}}
}

// ctype — 응답 Content-Type 의 미디어타입(파라미터 제외·소문자). 이슈 #54.
// 트리아지가 "브라우저가 이걸 렌더링하는가"를 판단하는 유일한 근거다.
func ctype(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	raw := resp.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(raw); err == nil {
		return strings.ToLower(mt)
	}
	return strings.ToLower(strings.TrimSpace(strings.Split(raw, ";")[0]))
}

// rendersMarkup — 브라우저가 이 미디어타입을 마크업으로 렌더링하는가 (이슈 #54).
//
// 빈 값(헤더 없음)은 true 다. 브라우저가 내용을 스니핑해 HTML 로 볼 수 있으므로,
// 모른다는 이유로 발견을 지우지 않는다 — 오탐을 줄이려다 정탐을 지우면 도구가 나빠진다.
// XML 계열을 포함하는 이유도 같다: XHTML·SVG 로 해석되면 스크립트가 실행될 수 있다.
func rendersMarkup(ct string) bool {
	switch ct {
	case "", "text/html", "application/xhtml+xml", "image/svg+xml", "application/xml", "text/xml":
		return true
	}
	return false
}
