// Package liveness — 정찰 라이브니스 검증 (이슈 #26).
//
// 크롤러의 정규식 추출물과 링크 추종 결과에는 실재하지 않는 경로가 섞인다.
// i18n 키·CSS 경로·SPA 클라이언트 라우트가 그대로 스캔 대상이 되면 오탐과 낭비를 만든다.
// Juice Shop static 실측 기준 발견 84건 중 오탐이 71건(83.5%)이었다.
//
// ★ 상태코드로는 판정할 수 없다. SPA 는 없는 경로에도 200 + index.html 을 준다.
// 그래서 먼저 "존재할 리 없는 경로"로 baseline 을 잡고, 후보 응답이 그 baseline 과
// 같은 모양이면 soft-404 로 본다.
//
// ★ 404 라고 지우지 않는다. unverified 로 강등할 뿐이다 — 삭제하면 근거가 사라져
// 왜 제외됐는지 재현할 수 없다. 트리에는 남고 endpoints.Targets() 에서만 빠진다.
package liveness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

const (
	rateLimit   = 120 * time.Millisecond // 크롤러·인제스터와 동일 (FR-3.2)
	maxBody     = 1 << 20
	maxProbes   = 500 // 한 번의 검증에서 보낼 최대 요청 수
	sizeTolPct  = 2   // 본문 길이가 baseline 대비 이 % 이내면 같은 모양으로 본다
	baselineCnt = 2   // baseline 확보용 무작위 경로 수
)

// Report — 검증 1회 결과.
type Report struct {
	Candidates  int      `json:"candidates"` // 프로브 대상(crawl-link·static-regex) 수
	Probed      int      `json:"probed"`     // 실제로 보낸 요청 수
	Demoted     int      `json:"demoted"`    // unverified 로 강등한 수
	Skipped     int      `json:"skipped"`    // 면제 등급이라 건너뛴 수
	Errors      int      `json:"errors"`
	Baseline    string   `json:"baseline"` // 잡아낸 soft-404 시그니처 ("" = 없음)
	DemotedList []string `json:"demoted_list,omitempty"`
	Duration    string   `json:"duration"`
}

// sig — 응답의 "모양". soft-404 비교에 쓴다.
type sig struct {
	status int
	ctype  string
	size   int64
	hash   string // 본문 해시(GET 으로 받았을 때만)
}

func (s sig) String() string {
	if s.status == 0 {
		return ""
	}
	return fmt.Sprintf("%d %s %dB", s.status, shortType(s.ctype), s.size)
}

// Run — 트리의 프로브 대상 엔드포인트를 검증하고 실재하지 않는 것을 강등한다.
func Run(ctx context.Context, tree *endpoints.Tree, client *http.Client) Report {
	start := time.Now()
	rep := Report{}

	// 1) 후보 수집 — 면제 등급은 요청조차 보내지 않는다.
	type cand struct{ scheme, host, path, source string }
	var cands []cand
	byHost := map[string]string{} // host → scheme (baseline 확보용)
	for _, t := range tree.TargetsAll() {
		if !endpoints.NeedsProbe(t.Source) {
			rep.Skipped++
			continue
		}
		sc := t.Scheme
		if sc == "" {
			sc = "https"
		}
		cands = append(cands, cand{sc, t.Host, t.Path, t.Source})
		byHost[t.Host] = sc
	}
	rep.Candidates = len(cands)
	if len(cands) == 0 {
		rep.Duration = time.Since(start).String()
		return rep
	}

	p := &prober{ctx: ctx, client: client, rep: &rep}

	// 2) 호스트별 baseline — 존재할 리 없는 경로의 응답 모양.
	baselines := map[string]sig{}
	for host, sc := range byHost {
		baselines[host] = p.baseline(sc, host)
		if b := baselines[host]; b.status != 0 && rep.Baseline == "" {
			rep.Baseline = host + " → " + b.String()
		}
	}

	// 3) 후보 프로브 → 강등.
	for _, c := range cands {
		if p.rep.Probed >= maxProbes || ctx.Err() != nil {
			break
		}
		got, ok := p.probe(c.scheme, c.host, c.path)
		if !ok {
			continue // 요청 실패는 강등 근거가 못 된다
		}
		if alive(c.path, got, baselines[c.host]) {
			continue
		}
		tree.MarkUnverified(c.host, c.path)
		rep.Demoted++
		if len(rep.DemotedList) < 20 {
			rep.DemotedList = append(rep.DemotedList, c.path+" ("+c.source+", "+got.String()+")")
		}
	}

	rep.Duration = time.Since(start).String()
	log.Printf("[LIVE] 후보=%d 프로브=%d 강등=%d 면제=%d baseline=%q (%s)",
		rep.Candidates, rep.Probed, rep.Demoted, rep.Skipped, rep.Baseline, rep.Duration)
	return rep
}

// alive — 응답이 "실재한다"를 뜻하는가.
//
// path 는 루트 예외 판정에만 쓴다. SPA 의 셸 HTML 은 곧 "/" 의 진짜 내용이라
// baseline 과 같은 모양으로 보이는데, 서버가 응답한 이상 루트는 실재한다.
// 여기서 걸러내면 크롤 시작점이 통째로 사라진다.
func alive(path string, got, base sig) bool {
	if path == "" || path == "/" {
		return true
	}
	switch {
	case got.status == 404 || got.status == 410:
		return false
	case got.status == 401 || got.status == 403:
		// ★ 인증 벽 뒤 엔드포인트다. 죽은 것으로 강등하면 재현율이 무너진다.
		return true
	case got.status >= 500:
		return true // 서버 오류는 부재의 증거가 아니다
	case got.status >= 300 && got.status < 400:
		return true // 리다이렉트 자체는 실재 신호로 본다
	}
	if base.status == 0 {
		return true // baseline 을 못 잡았으면 판정하지 않는다
	}
	return !sameShape(got, base)
}

// sameShape — soft-404 판정. baseline 과 같은 모양이면 실재하지 않는 것으로 본다.
func sameShape(a, b sig) bool {
	if a.status != b.status || shortType(a.ctype) != shortType(b.ctype) {
		return false
	}
	if a.hash != "" && b.hash != "" {
		return a.hash == b.hash
	}
	if a.size == 0 || b.size == 0 {
		return a.size == b.size
	}
	diff := a.size - b.size
	if diff < 0 {
		diff = -diff
	}
	return diff*100 <= b.size*sizeTolPct
}

func shortType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

type prober struct {
	ctx    context.Context
	client *http.Client
	rep    *Report
}

// baseline — 존재할 리 없는 경로 몇 개를 찔러 soft-404 시그니처를 잡는다.
// 응답이 서로 다르면(랜덤 요소가 있으면) baseline 없음으로 두고 판정을 포기한다.
func (p *prober) baseline(scheme, host string) sig {
	probes := []string{
		"/ava-liveness-probe-does-not-exist-0",
		"/ava-liveness-probe-does-not-exist-1/nested",
	}
	var first sig
	for i, path := range probes[:baselineCnt] {
		got, ok := p.probe(scheme, host, path)
		if !ok {
			return sig{}
		}
		if got.status == 404 || got.status == 410 {
			return sig{} // 정직하게 404 를 주는 서버다. soft-404 비교가 필요 없다.
		}
		if i == 0 {
			first = got
			continue
		}
		if !sameShape(got, first) {
			return sig{} // 응답이 매번 다르다 → 비교 불가
		}
	}
	return first
}

// probe — GET 으로 후보를 찔러 응답 모양을 잰다.
//
// HEAD 를 먼저 쓰고 싶지만 soft-404 판정에는 본문 비교가 필요하다. HEAD 는 본문을 주지 않고
// Content-Length 도 없을 수 있어(Juice Shop 이 그렇다) 판정 근거가 사라진다. 그래서 GET 을
// 쓰되 본문을 1MB 로 자르고 레이트리밋을 건다.
func (p *prober) probe(scheme, host, path string) (sig, bool) {
	u := &url.URL{Scheme: scheme, Host: host, Path: path}
	if allowed, _ := scope.Allowed(u.Hostname(), u.Path); !allowed {
		return sig{}, false // 스코프 밖으로는 아무것도 내보내지 않는다 (FR-2.1)
	}
	req, err := http.NewRequestWithContext(p.ctx, "GET", u.String(), nil)
	if err != nil {
		p.rep.Errors++
		return sig{}, false
	}
	auth.Default().Inject(req)
	time.Sleep(rateLimit)
	resp, err := p.client.Do(req)
	p.rep.Probed++
	if err != nil {
		p.rep.Errors++
		return sig{}, false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	sum := sha256.Sum256(b)
	return sig{
		status: resp.StatusCode,
		ctype:  resp.Header.Get("Content-Type"),
		size:   int64(len(b)),
		hash:   hex.EncodeToString(sum[:8]),
	}, true
}
