package detector

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/finding"
)

// ── 외부 도구 어댑터 (FR-3.4) ─────────────────────────────────────
// 로컬 설정의 경로에서 도구를 찾아 실행하고 출력을 finding으로 정규화.
// 실행 전 존재·버전 검증. 미설치면 우아하게 스킵.

var (
	toolMu    sync.RWMutex
	toolPaths = map[string]string{}
)

// SetToolPaths — 도구 실행 경로 지정 (local.config §4). 비면 PATH 탐색.
func SetToolPaths(m map[string]string) {
	toolMu.Lock()
	defer toolMu.Unlock()
	toolPaths = map[string]string{}
	for k, v := range m {
		toolPaths[k] = v
	}
}

// resolveTool — 설정 경로(존재 시) 또는 PATH에서 도구 실행파일 찾기.
func resolveTool(name string) (string, bool) {
	toolMu.RLock()
	p := toolPaths[name]
	toolMu.RUnlock()
	if p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	if lp, err := exec.LookPath(name); err == nil {
		return lp, true
	}
	return "", false
}

// ToolBased — 외부 도구 기반 Detector (존재·버전 노출용, list_detectors).
type ToolBased interface {
	Tool() string
	Available() (bool, string) // 사용가능? + 버전/사유
}

func runTool(ctx context.Context, stdin string, path string, args ...string) string {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, _ := cmd.CombinedOutput()
	return string(out)
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func match(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// ── sslscan (표준 도구; 미설치 시 스킵) ───────────────────────────
type sslscanTool struct{}

func (sslscanTool) ID() string        { return "sslscan" }
func (sslscanTool) Name() string      { return "취약 SSL/TLS 프로토콜·암호 (sslscan)" }
func (sslscanTool) Destructive() bool { return false }
func (sslscanTool) Tool() string      { return "sslscan" }
func (sslscanTool) Available() (bool, string) {
	p, ok := resolveTool("sslscan")
	if !ok {
		return false, "미설치"
	}
	return true, firstLine(runTool(context.Background(), "", p, "--version"))
}

func (sslscanTool) Detect(ctx context.Context, t endpoints.Target, _ *http.Client, _ *auth.Injector) []finding.Finding {
	p, ok := resolveTool("sslscan")
	if !ok {
		log.Printf("[TOOL] sslscan 미설치 — 스킵")
		return nil
	}
	throttle()
	out := runTool(ctx, "", p, "--no-colour", t.Host+":443")
	var weak []string
	for _, proto := range []string{"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"} {
		// sslscan은 "Enabled" 로 지원 프로토콜 표기
		if regexp.MustCompile(proto + `\s+enabled`).MatchString(out) {
			weak = append(weak, proto)
		}
	}
	if len(weak) == 0 {
		return nil
	}
	return []finding.Finding{{
		Vuln: "취약한 SSL/TLS 프로토콜 지원", Severity: "medium", Host: t.Host, Path: t.Path, Method: "TLS",
		Kind: "tool", Detector: "sslscan", Confidence: "high",
		Evidence: "지원: " + strings.Join(weak, ", "),
	}}
}

// ── openssl s_client (설치됨; TLS 프로토콜·암호 점검) ──────────────
type opensslTLSTool struct{}

var (
	reProto  = regexp.MustCompile(`Protocol\s*:\s*(\S+)`)
	reCipher = regexp.MustCompile(`Cipher\s*:\s*(\S+)`)
)

func (opensslTLSTool) ID() string        { return "openssl-tls" }
func (opensslTLSTool) Name() string      { return "TLS 구성 점검 (openssl)" }
func (opensslTLSTool) Destructive() bool { return false }
func (opensslTLSTool) Tool() string      { return "openssl" }
func (opensslTLSTool) Available() (bool, string) {
	p, ok := resolveTool("openssl")
	if !ok {
		return false, "미설치"
	}
	return true, firstLine(runTool(context.Background(), "", p, "version"))
}

func (opensslTLSTool) Detect(ctx context.Context, t endpoints.Target, _ *http.Client, _ *auth.Injector) []finding.Finding {
	p, ok := resolveTool("openssl")
	if !ok {
		log.Printf("[TOOL] openssl 미설치 — 스킵")
		return nil
	}
	throttle()
	out := runTool(ctx, "Q\n", p, "s_client", "-connect", t.Host+":443", "-servername", t.Host)
	proto := match(reProto, out)
	cipher := match(reCipher, out)
	if proto == "" {
		return nil // 핸드셰이크 실패/파싱 불가
	}
	sev, vuln := "info", "TLS 구성 정보"
	switch proto {
	case "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1":
		sev, vuln = "medium", "약한 TLS 버전 협상"
	}
	return []finding.Finding{{
		Vuln: vuln, Severity: sev, Host: t.Host, Path: t.Path, Method: "TLS",
		Kind: "tool", Detector: "openssl-tls", Confidence: "high",
		Evidence: fmt.Sprintf("protocol=%s cipher=%s", proto, cipher),
	}}
}
