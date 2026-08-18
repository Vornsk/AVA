// Package discover — 정찰 능동 콘텐츠 발견 (이슈 #27).
//
// 링크·명세·트래픽 어디에도 안 걸리는 unlinked 공격면(백업 파일·.git·설정·로그 디렉터리)은
// 실사용 진단에서 중요한데 지금까지의 정찰로는 영원히 못 찾는다. Juice Shop 실측 기준
// /support/logs 와 /encryptionkeys 는 디렉터리 목록이 그대로 열려 있는데도 링크가 없어
// 크롤·인제스트로는 도달하지 못한다.
//
// ★ 기본 비활성(옵트인)이다. 능동 탐색은 파괴성·소음·법적 경계가 있어 안전장치가 전제다.
//
//	· 옵트인 — Options.Discover 를 켜야만 요청이 나간다
//	· GET only·비파괴 — wordlist 에 상태를 바꿀 만한 경로를 넣지 않는다
//	· 스코프 하드 게이트(FR-2.1) · 크롤러와 같은 120ms 레이트리밋
//	· 요청 예산 상한 — 넘으면 중단하고 그 사실을 리포트에 남긴다
//	· 감사 기록 — 누가 언제 켰는지 남는다(호출자가 audit.Record)
//
// ★ 등록 전에 실재를 판정한다. 라이브니스(#26)는 "일단 등록 후 강등"이지만 여기는 반대다 —
// 트리에 쓰레기를 넣었다가 지우는 것보다 낫고 unverified 노드가 쌓이지 않는다.
// 판정은 internal/recon/probe 를 그대로 쓴다(#26 과 같은 캘리브레이션).
package discover

import (
	"bufio"
	"context"
	_ "embed"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/recon/probe"
)

//go:embed wordlist.txt
var wordlistRaw string

// DefaultBudget — 기본 요청 예산. 120ms 레이트리밋이면 500건 ≈ 1분이다.
const DefaultBudget = 500

// Report — 능동 발견 1회 결과.
type Report struct {
	Words     int      `json:"words"`    // wordlist 항목 수
	Probed    int      `json:"probed"`   // 실제로 보낸 요청 수(기준 지문 포함)
	Found     int      `json:"found"`    // 실재가 확인돼 등록한 수
	Rejected  int      `json:"rejected"` // 프로브했으나 실재하지 않아 버린 수
	Errors    int      `json:"errors"`
	Budget    int      `json:"budget"`    // 적용된 요청 예산
	Exhausted bool     `json:"exhausted"` // 예산 소진으로 중단했는가
	Baseline  string   `json:"baseline"`  // 잡아낸 soft-404 기준 ("" = 없음)
	FoundList []string `json:"found_list,omitempty"`
	Duration  string   `json:"duration"`
}

// Words — embed 된 wordlist 항목(주석·빈 줄 제외, 중복 제거, 순서 유지).
func Words() []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(wordlistRaw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := "/" + strings.TrimPrefix(line, "/")
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// Run — seed 호스트에 대해 wordlist 를 프로브하고 실재가 확인된 경로만 등록한다.
//
// budget 이 0 이하면 DefaultBudget 을 쓴다. 예산은 기준 지문 확보 요청까지 포함해 센다 —
// "이 기능이 대상 서버에 몇 건을 보내는가"가 사용자가 알아야 할 숫자이기 때문이다.
func Run(ctx context.Context, tree *endpoints.Tree, seed string, client *http.Client, budget int) Report {
	start := time.Now()
	if budget <= 0 {
		budget = DefaultBudget
	}
	words := Words()
	rep := Report{Words: len(words), Budget: budget}

	base, err := url.Parse(seed)
	if err != nil || base.Host == "" {
		rep.Errors++
		rep.Duration = time.Since(start).String()
		return rep
	}
	scheme := base.Scheme
	if scheme == "" {
		scheme = "https"
	}

	p := probe.New(ctx, client)
	sig404 := p.Calibrate(scheme, base.Host)
	rep.Baseline = sig404.String()

	for _, path := range words {
		if ctx.Err() != nil {
			break
		}
		if p.Probes >= budget {
			rep.Exhausted = true
			break
		}
		got, ok := p.Probe(scheme, base.Host, path)
		if !ok {
			continue // 스코프 밖이거나 요청 실패 — 등록 근거가 없다
		}
		// 능동 발견은 오탐 0 이 우선이다(완료기준). 5xx 는 "그런 경로 없음"을 서버가 500 으로
		// 표현하는 경우가 많아(Juice Shop: 500 "Unexpected path: /api") 등록하지 않는다.
		// 라이브니스(#26)는 반대로 5xx 를 살리지만, 그쪽은 이미 등록된 것을 지키는 입장이라 다르다.
		if got.Status >= 500 || !probe.Exists(path, got, sig404) {
			rep.Rejected++
			continue
		}
		tree.RecordFrom(endpoints.SrcDiscover, scheme, base.Host, "GET", path,
			nil, auth.Default().Enabled(), "")
		rep.Found++
		if len(rep.FoundList) < 30 {
			rep.FoundList = append(rep.FoundList, path+" ("+got.String()+")")
		}
	}

	rep.Probed, rep.Errors = p.Probes, p.Errors
	rep.Duration = time.Since(start).String()
	log.Printf("[DISC] %s  wordlist=%d 프로브=%d 발견=%d 버림=%d 예산=%d%s baseline=%q (%s)",
		base.Host, rep.Words, rep.Probed, rep.Found, rep.Rejected, rep.Budget,
		exhaustedMark(rep.Exhausted), rep.Baseline, rep.Duration)
	for _, f := range rep.FoundList {
		log.Printf("[DISC]   + %s", f) // 무엇을 찾았는지 남긴다 — 정답셋 대조·감사에 필요하다
	}
	if rep.Exhausted {
		log.Printf("[DISC] ★ 예산 %d 건 소진으로 중단 — wordlist %d 항목 중 일부만 확인했다",
			rep.Budget, rep.Words)
	}
	return rep
}

func exhaustedMark(b bool) string {
	if b {
		return "(소진)"
	}
	return ""
}
