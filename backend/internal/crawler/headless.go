// 헤드리스 크롤(옵트인): Chrome를 띄워 JS를 실제 실행·렌더한 DOM에서 링크/폼/API를 수집한다.
// SPA(클라이언트 렌더)까지 완전 크롤. Chrome 런타임이 필요하므로 폐쇄망 단일 exe 목표와 상충 →
// 기본은 static, 사용자가 명시적으로 선택할 때만 사용. Chrome 미설치 시 HeadlessAvailable=false.
package crawler

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

var (
	hlOnce  sync.Once
	hlAvail bool
)

// HeadlessAvailable — 헤드리스 Chrome을 띄울 수 있는가(1회 프로브 후 캐시). 미설치/오프라인이면 false.
func HeadlessAvailable() bool {
	hlOnce.Do(func() {
		allocCtx, cancel := chromedp.NewExecAllocator(context.Background(),
			append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", true))...)
		defer cancel()
		ctx, cancel2 := chromedp.NewContext(allocCtx)
		defer cancel2()
		ctx, cancel3 := context.WithTimeout(ctx, 10*time.Second)
		defer cancel3()
		hlAvail = chromedp.Run(ctx, chromedp.Navigate("about:blank")) == nil
	})
	return hlAvail
}

// runHeadless — Chrome로 렌더링하며 BFS 크롤. 렌더된 DOM은 static 추출기(extract/extractAPIEndpoints)를
// 재사용하고, 페이지가 실제로 호출한 네트워크 요청(XHR/fetch)도 in-scope면 공격면에 등록한다.
func (j *job) runHeadless(seed string, opts Options) {
	j.ingestOnce(seed, opts, &http.Client{Timeout: 15 * time.Second})   // 명세 선행 인제스트 (#25)
	j.discoverOnce(seed, opts, &http.Client{Timeout: 15 * time.Second}) // 옵트인일 때만 (#27)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(j.ctx,
		append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("ignore-certificate-errors", true), // MITM/자체서명 대상
		)...)
	defer cancelAlloc()
	bctx, cancelB := chromedp.NewContext(allocCtx)
	defer cancelB()

	// 네트워크 요청 캡처(페이지가 실제 호출한 XHR/fetch URL).
	var netMu sync.Mutex
	netHits := map[string]bool{}
	chromedp.ListenTarget(bctx, func(ev interface{}) {
		if e, ok := ev.(*network.EventRequestWillBeSent); ok {
			netMu.Lock()
			netHits[e.Request.URL] = true
			netMu.Unlock()
		}
	})

	// 브라우저 기동 + 네트워크 활성 + 인증 쿠키 주입.
	if err := chromedp.Run(bctx, network.Enable(), setAuthCookies(seed)); err != nil {
		j.mu.Lock()
		j.res.Errors++
		j.mu.Unlock()
		j.setStatus("중단") // Chrome 미기동
		return
	}

	visited := map[string]bool{}
	foundEP := map[string]bool{}
	queue := []item{{seed, 0}}

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
	drainNet := func() {
		netMu.Lock()
		hits := make([]string, 0, len(netHits))
		for u := range netHits {
			hits = append(hits, u)
		}
		netHits = map[string]bool{}
		netMu.Unlock()
		for _, h := range hits {
			hu, err := url.Parse(h)
			if err != nil || (hu.Scheme != "http" && hu.Scheme != "https") {
				continue
			}
			if ok, _ := scope.Allowed(hu.Hostname(), hu.Path); ok {
				recordFound(hu, endpoints.SrcHeadlessXHR) // 앱이 실제로 호출한 XHR/fetch
			}
		}
	}

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
			continue
		}

		html, err := renderPage(bctx, it.u)
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

		recordFound(u, endpoints.SrcCrawlLink) // 렌더된 DOM 링크를 따라간 것
		drainNet()                             // 이 페이지가 부른 XHR/fetch
		if pages >= opts.MaxPages {
			break
		}

		// 렌더된 DOM에 static 추출기 재사용.
		links, forms := extract(html, u)
		for _, l := range links {
			if lu, e := url.Parse(l); e == nil && !visited[normKey(lu)] {
				queue = append(queue, item{l, it.depth + 1})
			}
		}
		for _, f := range forms {
			recordForm(f, endpoints.SrcCrawlLink)
		}
		for _, ep := range extractAPIEndpoints(html, u) {
			if eu, e := url.Parse(ep); e == nil {
				recordFound(eu, endpoints.SrcStaticRegex) // 렌더된 HTML 정규식 추출물
			}
		}
		j.mu.Lock()
		j.res.Queued = len(queue)
		j.mu.Unlock()
		time.Sleep(120 * time.Millisecond)
	}
	j.verifyOnce(opts, &http.Client{Timeout: 15 * time.Second}) // 실재 검증 (#26)
	j.setStatus("완료")
}

// renderPage — URL 로 이동, JS 정착 대기 후 렌더된 outerHTML 반환.
func renderPage(ctx context.Context, rawURL string) (string, error) {
	tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var html string
	err := chromedp.Run(tctx,
		chromedp.Navigate(rawURL),
		chromedp.Sleep(1500*time.Millisecond), // 클라이언트 렌더 정착
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	)
	return html, err
}

// setAuthCookies — auth 주입기의 쿠키를 브라우저에 심는다(Inject 재사용해 실제 name/value 추출).
func setAuthCookies(seed string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		req, err := http.NewRequest("GET", seed, nil)
		if err != nil {
			return nil
		}
		auth.Default().Inject(req)
		u, err := url.Parse(seed)
		if err != nil {
			return nil
		}
		for _, c := range req.Cookies() {
			_ = network.SetCookie(c.Name, c.Value).WithDomain(u.Hostname()).WithPath("/").Do(ctx)
		}
		return nil
	})
}
