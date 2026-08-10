package detector

import (
	"os"
	"regexp"
	"testing"
)

func TestResolveTool(t *testing.T) {
	// 존재하는 파일(테스트 바이너리)을 경로로 지정 → resolve 성공
	SetToolPaths(map[string]string{"faketool": os.Args[0]})
	defer SetToolPaths(nil)

	if p, ok := resolveTool("faketool"); !ok || p == "" {
		t.Error("configured existing path should resolve")
	}
	if _, ok := resolveTool("definitely-not-a-real-tool-xyz-123"); ok {
		t.Error("nonexistent tool should not resolve")
	}
}

func TestFirstLineAndMatch(t *testing.T) {
	if firstLine("abc\ndef") != "abc" {
		t.Errorf("firstLine = %q", firstLine("abc\ndef"))
	}
	re := regexp.MustCompile(`Protocol\s*:\s*(\S+)`)
	if got := match(re, "  Protocol  : TLSv1.3\n  Cipher : X"); got != "TLSv1.3" {
		t.Errorf("match = %q, want TLSv1.3", got)
	}
	if got := match(re, "no match here"); got != "" {
		t.Errorf("no-match should be empty, got %q", got)
	}
}

func TestCatalogToolAvailability(t *testing.T) {
	SetToolPaths(nil)
	var openssl, sslscan bool
	for _, i := range Catalog() {
		switch i.ID {
		case "openssl-tls":
			openssl = true
			if i.Tool != "openssl" || i.Available == nil {
				t.Errorf("openssl-tls catalog: tool=%q available=%v", i.Tool, i.Available)
			}
		case "sslscan":
			sslscan = true
		}
	}
	if !openssl || !sslscan {
		t.Errorf("tool detectors missing from catalog (openssl=%v sslscan=%v)", openssl, sslscan)
	}
}
