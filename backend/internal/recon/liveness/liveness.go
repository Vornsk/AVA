// Package liveness — 정찰 라이브니스 검증 (이슈 #26).
//
// 크롤러의 정규식 추출물과 링크 추종 결과에는 실재하지 않는 경로가 섞인다.
// i18n 키·CSS 경로·SPA 클라이언트 라우트가 그대로 스캔 대상이 되면 오탐과 낭비를 만든다.
// Juice Shop static 실측 기준 발견 85건 중 오탐이 69건(81.2%)이었다.
//
// 실재 판정은 internal/recon/probe 가 한다 — 상태코드로는 갈리지 않으므로(SPA 는 없는 경로에도
// 200 을 준다) 기준 지문을 잡아 본문 모양을 비교한다. 능동 발견(#27)도 같은 판정을 쓴다.
//
// ★ 404 라고 지우지 않는다. unverified 로 강등할 뿐이다 — 삭제하면 근거가 사라져
// 왜 제외됐는지 재현할 수 없다. 트리에는 남고 endpoints.Targets() 에서만 빠진다.
package liveness

import (
	"context"
	"log"
	"net/http"
	"time"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/recon/probe"
)

// maxProbes — 한 번의 검증에서 보낼 최대 요청 수.
const maxProbes = 500

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

// Run — 트리의 프로브 대상 엔드포인트를 검증하고 실재하지 않는 것을 강등한다.
func Run(ctx context.Context, tree *endpoints.Tree, client *http.Client) Report {
	start := time.Now()
	rep := Report{}

	// 1) 후보 수집 — 면제 등급은 요청조차 보내지 않는다.
	type cand struct{ scheme, host, path, source string }
	var cands []cand
	byHost := map[string]string{} // host → scheme (기준 지문 확보용)
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

	p := probe.New(ctx, client)

	// 2) 호스트별 기준 지문.
	bases := map[string]probe.Sig{}
	for host, sc := range byHost {
		bases[host] = p.Calibrate(sc, host)
		if b := bases[host]; b.OK() && rep.Baseline == "" {
			rep.Baseline = host + " → " + b.String()
		}
	}

	// 3) 후보 프로브 → 강등.
	for _, c := range cands {
		if p.Probes >= maxProbes || ctx.Err() != nil {
			break
		}
		got, ok := p.Probe(c.scheme, c.host, c.path)
		if !ok {
			continue // 요청 실패는 강등 근거가 못 된다
		}
		if probe.Exists(c.path, got, bases[c.host]) {
			continue
		}
		tree.MarkUnverified(c.host, c.path)
		rep.Demoted++
		if len(rep.DemotedList) < 20 {
			rep.DemotedList = append(rep.DemotedList, c.path+" ("+c.source+", "+got.String()+")")
		}
	}

	rep.Probed, rep.Errors = p.Probes, p.Errors
	rep.Duration = time.Since(start).String()
	log.Printf("[LIVE] 후보=%d 프로브=%d 강등=%d 면제=%d baseline=%q (%s)",
		rep.Candidates, rep.Probed, rep.Demoted, rep.Skipped, rep.Baseline, rep.Duration)
	return rep
}
