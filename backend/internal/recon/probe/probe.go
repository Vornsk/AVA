// Package probe — 응답 지문화와 soft-404 캘리브레이션 (이슈 #26 → #27 공용).
//
// "이 경로가 실재하는가"를 판정하려면 상태코드만으로는 부족하다. SPA 는 없는 경로에도
// 200 + index.html 을 준다(Juice Shop 실측: 어떤 경로든 200 text/html 9393B).
// 그래서 먼저 "존재할 리 없는 경로"를 찔러 기준 응답을 지문화하고, 후보 응답이 그 기준과
// 같은 모양이면 실재하지 않는 것으로 본다.
//
// 라이브니스 검증(#26)과 능동 발견(#27)이 같은 판정을 써야 하므로 여기로 분리했다 —
// 두 곳에 따로 구현하면 판정이 어긋난다.
package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/scope"
)

const (
	// RateLimit — 크롤러·인제스터와 동일 (FR-3.2).
	RateLimit = 120 * time.Millisecond
	maxBody   = 1 << 20
	// sizeTolPct — 본문 길이가 기준 대비 이 % 이내면 같은 모양으로 본다.
	sizeTolPct = 2
	// calibrateCnt — 캘리브레이션에 쓸 무작위 경로 수. 늘리면 정확도가 아니라 요청 수가 는다
	// (같은 catch-all 이 여러 번 나오는 것을 확인할 뿐). 두 번이면 "매번 다른 응답"을 걸러낼 수 있다.
	calibrateCnt = 2
)

// Sig — 응답의 "모양". soft-404 비교 단위.
type Sig struct {
	Status int
	Ctype  string
	Size   int64
	Hash   string // 본문 해시(앞 8바이트)
}

// OK — 지문이 유효한가(요청이 성공했는가).
func (s Sig) OK() bool { return s.Status != 0 }

func (s Sig) String() string {
	if s.Status == 0 {
		return ""
	}
	return fmt.Sprintf("%d %s %dB", s.Status, ShortType(s.Ctype), s.Size)
}

// Client — 프로브 실행기. 요청 수와 오류 수를 누적한다.
type Client struct {
	ctx    context.Context
	http   *http.Client
	Probes int // 보낸 요청 수
	Errors int
}

// New — 프로브 실행기.
func New(ctx context.Context, c *http.Client) *Client { return &Client{ctx: ctx, http: c} }

// Probe — GET 으로 경로를 찔러 응답 모양을 잰다. 스코프 밖이면 요청하지 않는다 (FR-2.1).
//
// HEAD 를 쓰지 않는 이유: soft-404 판정에는 본문 비교가 필요한데 HEAD 는 본문을 주지 않고
// Content-Length 도 없을 수 있다(Juice Shop 이 그렇다). 대신 본문을 1MB 로 자르고
// 레이트리밋을 건다.
func (c *Client) Probe(scheme, host, path string) (Sig, bool) {
	sig, _, ok := c.ProbeURL(&url.URL{Scheme: scheme, Host: host, Path: path})
	return sig, ok
}

// ProbeURL — 임의 URL(쿼리 포함)을 GET 해 응답 모양과 본문을 함께 잰다. 스코프 밖이면 (,,false).
// 파라미터 마이닝(#40)은 본문 반사를 봐야 하므로 본문이 필요하다. 본문은 1MB 로 자른다.
func (c *Client) ProbeURL(u *url.URL) (Sig, string, bool) {
	if allowed, _ := scope.Allowed(u.Hostname(), u.Path); !allowed {
		return Sig{}, "", false // 스코프 밖으로는 아무것도 내보내지 않는다
	}
	req, err := http.NewRequestWithContext(c.ctx, "GET", u.String(), nil)
	if err != nil {
		c.Errors++
		return Sig{}, "", false
	}
	auth.Default().Inject(req)
	time.Sleep(RateLimit)
	resp, err := c.http.Do(req)
	c.Probes++
	if err != nil {
		c.Errors++
		return Sig{}, "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	sum := sha256.Sum256(b)
	return Sig{
		Status: resp.StatusCode,
		Ctype:  resp.Header.Get("Content-Type"),
		Size:   int64(len(b)),
		Hash:   hex.EncodeToString(sum[:8]),
	}, string(b), true
}

// Calibrate — 존재할 리 없는 경로를 찔러 soft-404 기준 지문을 잡는다.
//
// 다음 두 경우에는 빈 Sig 를 돌려주고 판정을 포기한다.
//   - 서버가 정직하게 404 를 준다 → 기준 비교가 필요 없다(상태코드로 충분).
//   - 응답이 매번 다르다 → 비교가 불가능하다. 근거 없는 판정을 하느니 안 한다.
func (c *Client) Calibrate(scheme, host string) Sig {
	paths := []string{
		"/ava-probe-does-not-exist-0",
		"/ava-probe-does-not-exist-1/nested",
	}
	var first Sig
	for i, p := range paths[:calibrateCnt] {
		got, ok := c.Probe(scheme, host, p)
		if !ok {
			return Sig{}
		}
		if got.Status == 404 || got.Status == 410 {
			return Sig{}
		}
		if i == 0 {
			first = got
			continue
		}
		if !SameShape(got, first) {
			return Sig{}
		}
	}
	return first
}

// SameShape — 두 응답이 같은 모양인가. 기준 지문과 같으면 soft-404 다.
func SameShape(a, b Sig) bool {
	if a.Status != b.Status || ShortType(a.Ctype) != ShortType(b.Ctype) {
		return false
	}
	if a.Hash != "" && b.Hash != "" {
		return a.Hash == b.Hash
	}
	if a.Size == 0 || b.Size == 0 {
		return a.Size == b.Size
	}
	diff := a.Size - b.Size
	if diff < 0 {
		diff = -diff
	}
	return diff*100 <= b.Size*sizeTolPct
}

// Exists — 응답이 "이 경로는 실재한다"를 뜻하는가.
//
// path 는 루트 예외 판정에만 쓴다. SPA 셸 HTML 은 곧 "/" 의 진짜 내용이라 기준 지문과 같은
// 모양으로 보이는데, 서버가 응답한 이상 루트는 실재한다.
func Exists(path string, got, base Sig) bool {
	if path == "" || path == "/" {
		return true
	}
	switch {
	case got.Status == 404 || got.Status == 410:
		return false
	case got.Status == 401 || got.Status == 403:
		// 인증 벽 뒤 엔드포인트다. 죽은 것으로 보면 재현율이 무너진다.
		return true
	case got.Status >= 500:
		return true // 서버 오류는 부재의 증거가 아니다 (라이브니스: 우연히 터진 실 엔드포인트 보호)
	case got.Status >= 300 && got.Status < 400:
		return true // 리다이렉트 자체는 실재 신호로 본다
	}
	if !base.OK() {
		return true // 기준을 못 잡았으면 판정하지 않는다
	}
	return !SameShape(got, base)
}

// ShortType — content-type 에서 파라미터를 떼고 소문자로.
func ShortType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}
