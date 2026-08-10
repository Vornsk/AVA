// Command mitmclient — B-2 데모 (throwaway).
// 우리 Go 프로그램(orchestrator)이 MCP로 외부 프록시 도구(mitmproxy)를 제어한다.
// mitmproxy가 mitm_mcp_addon.py 와 함께 떠 있어야 함 (MCP: 127.0.0.1:8766).
// 실행: go run ./cmd/mitmclient   (또는 mitmclient.exe)
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "mitm-orchestrator", Version: "0.1.0"}, nil)

	transport := &mcp.StreamableClientTransport{Endpoint: "http://127.0.0.1:8766/mcp"}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Fatalf("mitmproxy MCP 연결 실패: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		log.Fatalf("ListTools 실패: %v", err)
	}
	fmt.Println("== mitmproxy가 MCP로 노출한 도구 ==")
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

	// Go가 외부 프록시(mitmproxy)의 캡처 상태를 MCP로 조회
	call("flow_count", map[string]any{})
	call("list_flows", map[string]any{"limit": 10})
}
