package bench

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"proxypoc/internal/crawler"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

// Reachable — 대상 base 가 응답하는가(기동 여부 프로브). 어떤 HTTP 응답이든 오면 true.
// Juice Shop 은 https://localhost 자기서명이라 InsecureSkipVerify 로 접속만 확인한다.
func Reachable(base string) bool {
	c := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := c.Get(base)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

// RunProfile — 한 프로파일로 정찰을 돌리고 발견 집합을 수집한다.
// 전역 트리를 Reset 해 프로파일 간 격리를 보장한다(이슈 #22의 실행 격리).
//
//	반환: 발견 엔드포인트(method 확장), 제품 구분 수(rawCount=팽창률 분자), 페이지수(≈요청수), 소요시간.
func RunProfile(seed, mode string, maxPages int, timeout time.Duration) (disc []Endpoint, rawCount, pages int, dur time.Duration, err error) {
	endpoints.Reset()

	// 크롤러는 scope.Allowed(host,path) 로 모든 fetch 를 게이트한다. 대상 호스트를 스코프에 넣는다.
	if u, perr := url.Parse(seed); perr == nil && u.Hostname() != "" {
		scope.Configure([]string{u.Hostname()}, nil, nil)
	}

	start := time.Now()
	res := crawler.Start(seed, crawler.Options{Mode: mode, MaxPages: maxPages})

	deadline := time.Now().Add(timeout)
	for {
		st, ok := crawler.Status(res.ID)
		if ok {
			res = st
		}
		if res.Status != "진행" {
			break
		}
		if time.Now().After(deadline) {
			_ = crawler.Cancel(res.ID)
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	dur = time.Since(start)

	// 발견 집합: 제품 트리의 Target(정규화 노드별 구체 경로)을 method 로 펼친다.
	for _, t := range endpoints.Targets() {
		for _, m := range t.Methods {
			disc = append(disc, Endpoint{Method: m, Path: t.Path})
		}
	}
	rawCount = len(disc) // 제품이 구분한 (method,path) 수 — 하네스 canonical 로 접히기 전
	return disc, rawCount, res.Pages, dur, nil
}
