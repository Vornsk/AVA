// Command mcpclient — B-1 데모 클라이언트.
// HTTP로 proxy-poc MCP 서버에 접속해 도구를 호출한다.
// "Go MCP 클라이언트가 우리 프록시를 MCP로 조회/제어" 를 증명.
// 실행: proxy-poc.exe 가 떠 있는 상태에서  go run ./cmd/mcpclient
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type emptyArgs struct{}

func main() {
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "proxy-poc-client", Version: "0.1.0"}, nil)

	transport := &mcp.StreamableClientTransport{Endpoint: "http://127.0.0.1:8765"}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Fatalf("MCP 연결 실패: %v", err)
	}
	defer session.Close()

	// 서버가 노출한 도구 목록
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		log.Fatalf("ListTools 실패: %v", err)
	}
	fmt.Println("== 서버가 노출한 MCP 도구 ==")
	for _, t := range tools.Tools {
		fmt.Printf("  - %s: %s\n", t.Name, t.Description)
	}

	call := func(name string, args any) {
		fmt.Printf("\n== call %s(%v) ==\n", name, args)
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			fmt.Printf("  에러: %v\n", err)
			return
		}
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				fmt.Println(tc.Text)
			}
		}
	}

	// 조회: 요약 → 최근 트래픽 → 엔드포인트 → LLM 판단 로그(dedup 캐시 확인)
	call("stats", emptyArgs{})
	call("recent_requests", map[string]any{"limit": 5})
	call("get_endpoint", map[string]any{"host": "httpbin.org", "path": "/get"})
	call("llm_decisions", emptyArgs{})

	// 제어: 스코프 추가 → 제거 (add/remove 짝 증명)
	call("add_scope_host", map[string]any{"host": "testphp.vulnweb.com"})
	call("remove_scope_host", map[string]any{"host": "testphp.vulnweb.com"})

	// 안전모드 가드레일 (FR-3.2): 켜면 파괴성 강제제외 → 스캔 skipped 로 확인 → 끔
	call("set_safe_mode", map[string]any{"on": true})
	call("run_scan", map[string]any{"detectors": []string{"destructive-demo"}, "allow_destructive": true})
	call("set_safe_mode", map[string]any{"on": false})

	// 점검항목표 (§6, 3계층): 스킴 → 전자금융 탭 항목(3계층 펼침)
	call("list_schemes", emptyArgs{})
	call("list_checkitems", map[string]any{"scheme": "전자금융"})

	// 자동화 진단 (§5.3): 페이로드셋(FR-3.7) 확인 → 페이로드 기반 반사탐지 → finding
	call("list_payloads", emptyArgs{})
	call("run_scan", map[string]any{"detectors": []string{"sec-headers", "reflected-input", "sensitive-data", "idor", "privesc", "sqli", "sqli-blind", "sqli-time", "path-traversal", "open-redirect", "csrf", "cookie-security", "http-method", "dir-indexing"}})
	// 파일 업로드(파괴적=대상에 마커 파일 생성) → allow_destructive 옵트인
	call("run_scan", map[string]any{"detectors": []string{"file-upload"}, "allow_destructive": true})
	time.Sleep(3 * time.Second)
	call("list_findings", emptyArgs{}) // finding 에 check_items 태그 확인 (§6)

	// 커버리지 (§6 ↔ §5.3): 스캔 후 스킴별 항목 커버 현황
	call("coverage_report", emptyArgs{})

	// 이행점검 (§5.5): 취약 finding replay·재평가 → 조치완료/미조치
	call("reverify", emptyArgs{})

	// 프로젝트 (§5.1): 목록·활성 프로젝트 조회 (생성/전환은 웹 UI에서)
	call("list_projects", emptyArgs{})
	call("get_active_project", emptyArgs{})
}
