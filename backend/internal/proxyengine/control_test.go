package proxyengine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

// TestCaptureToggle — 이슈 #5 핵심 완료 기준 검증:
// 캡처 ON이면 공용 트리에 기록되고 카운터가 증가하며, OFF면 기록·카운터 모두 멈추고,
// 다시 ON이면 재개된다. 스코프·판단 통과 등 기존 흐름은 캡처 상태와 무관하게 동작한다.
func TestCaptureToggle(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	proxy := httptest.NewServer(New(nil)) // 스테이지 없음 → 판단 통과
	defer proxy.Close()

	tu, _ := url.Parse(target.URL)
	scope.Add(tu.Hostname()) // 스코프는 hostname(포트 없음)으로 판단
	defer scope.Remove(tu.Hostname())
	authority := tu.Host // 엔드포인트 트리는 host[:port] authority 로 키를 잡음
	defer SetCapture(true)

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	do := func(path string) {
		resp, err := client.Get(target.URL + path)
		if err != nil {
			t.Fatalf("요청 실패 %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	// 캡처 ON → 기록됨 + 카운터 +1
	SetCapture(true)
	c0 := CapturedCount()
	do("/on-first")
	if got := CapturedCount(); got != c0+1 {
		t.Fatalf("캡처 ON: 카운터 증가 실패 (%d→%d)", c0, got)
	}
	if _, ok := endpoints.Find(authority, "/on-first"); !ok {
		t.Fatalf("캡처 ON: /on-first 엔드포인트 미기록")
	}

	// 캡처 OFF → 기록 안 됨 + 카운터 불변
	SetCapture(false)
	c1 := CapturedCount()
	do("/off-path")
	if got := CapturedCount(); got != c1 {
		t.Fatalf("캡처 OFF: 카운터가 증가함 (%d→%d)", c1, got)
	}
	if _, ok := endpoints.Find(authority, "/off-path"); ok {
		t.Fatalf("캡처 OFF: /off-path 가 기록됨(기록되면 안 됨)")
	}

	// 다시 ON → 재개
	SetCapture(true)
	c2 := CapturedCount()
	do("/on-second")
	if got := CapturedCount(); got != c2+1 {
		t.Fatalf("캡처 재개: 카운터 증가 실패 (%d→%d)", c2, got)
	}
	if _, ok := endpoints.Find(authority, "/on-second"); !ok {
		t.Fatalf("캡처 재개: /on-second 엔드포인트 미기록")
	}
}

// TestListenAddr — 리슨 주소 상태가 설정/조회된다.
func TestListenAddr(t *testing.T) {
	SetListenAddr("127.0.0.1:8080")
	if got := ListenAddr(); got != "127.0.0.1:8080" {
		t.Fatalf("ListenAddr=%q, want 127.0.0.1:8080", got)
	}
}
