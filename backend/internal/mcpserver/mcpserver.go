// Package mcpserver — MCP 오케스트레이션 계층.
// goproxy 프로세스가 노출하는 MCP 서버. 잡은 라이브 상태(엔드포인트·트래픽·스코프)를
// MCP 도구로 조회/제어한다. 전송은 StreamableHTTP(TCP) → AF_UNIX 안 씀.
//
//	(Burp MCP가 죽은 이유였던 JVM AF_UNIX self-pipe 문제를 회피)
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"os"

	"proxypoc/internal/advisor"
	"proxypoc/internal/audit"
	"proxypoc/internal/auth"
	"proxypoc/internal/bundle"
	"proxypoc/internal/checklist"
	"proxypoc/internal/coverage"
	"proxypoc/internal/detector"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/finding"
	"proxypoc/internal/llm"
	"proxypoc/internal/payload"
	"proxypoc/internal/profile"
	"proxypoc/internal/project"
	"proxypoc/internal/proxyengine"
	"proxypoc/internal/report"
	"proxypoc/internal/reverify"
	"proxypoc/internal/rules"
	"proxypoc/internal/scanengine"
	"proxypoc/internal/scope"
	"proxypoc/internal/tenant"
	"proxypoc/internal/traffic"
	"proxypoc/internal/user"
)

type emptyArgs struct{}

type hostArgs struct {
	Host string `json:"host"`
}

type getEndpointArgs struct {
	Host string `json:"host"`
	Path string `json:"path"`
}

type limitArgs struct {
	Limit int `json:"limit"`
}

type runScanArgs struct {
	AllowDestructive bool     `json:"allow_destructive,omitempty"`
	Hosts            []string `json:"hosts,omitempty"`         // 대상 호스트 필터 (비면 전체)
	PathContains     string   `json:"path_contains,omitempty"` // 대상 경로 부분일치 필터 (비면 전체)
	Detectors        []string `json:"detectors,omitempty"`     // 탐지기 id 선택 (비면 전체)
	LLMReview        bool     `json:"llm_review,omitempty"`    // finding LLM 오탐검토·조치문구 (FR-3.3)
	Auto             bool     `json:"auto,omitempty"`          // 공격면 넓은 대상만 자동선정 (FR-3.9)
	Profile          string   `json:"profile,omitempty"`       // 저장된 프로파일 사용 (FR-3.9)
}

type scanIDArgs struct {
	ID string `json:"id"`
}

type safeModeArgs struct {
	On bool `json:"on"`
}

type captureArgs struct {
	On bool `json:"on"`
}

type reverifyArgs struct {
	ScanRun string `json:"scan_run,omitempty"` // 특정 ScanRun의 finding만. 비면 전체
}

type diffArgs struct {
	From string `json:"from"` // 이전 ScanRun id
	To   string `json:"to"`   // 이후 ScanRun id
}

type schemeArgs struct {
	Scheme string `json:"scheme,omitempty"` // 비면 전체 스킴
}

type createProjectArgs struct {
	Name     string   `json:"name"`
	MainURL  string   `json:"main_url,omitempty"`
	Scope    []string `json:"scope,omitempty"`
	Schemes  []string `json:"schemes,omitempty"`
	Activate bool     `json:"activate,omitempty"` // 생성 후 활성화 + 엔진 적용
}

type projectIDArgs struct {
	ID string `json:"id"`
}

type exportProjectArgs struct {
	ID   string `json:"id"`
	Path string `json:"path,omitempty"` // 저장 경로. 비면 <name><ext>
}

type importProjectArgs struct {
	Path string `json:"path"`
}

type memberArgs struct {
	ID     string `json:"id"`      // project id
	UserID string `json:"user_id"` // 대상 사용자
}

type setCredsArgs struct {
	ID         string                           `json:"id"`
	Cookies    map[string]string                `json:"cookies,omitempty"`
	Headers    map[string]string                `json:"headers,omitempty"`
	Identities map[string]project.IdentityCreds `json:"identities,omitempty"`
}

type findingStatusArgs struct {
	ID      string `json:"id"`
	Status  string `json:"status"`  // 검토중 | 확정 | 오탐 | 보류 | 보고
	Version int    `json:"version"` // 낙관적 락: 마지막으로 읽은 버전
}

type setSchemesArgs struct {
	Schemes []string `json:"schemes,omitempty"` // 선택할 스킴들. 비면 선택 해제(전체)
}

type saveProfileArgs struct {
	Name         string   `json:"name"`
	Hosts        []string `json:"hosts,omitempty"`
	PathContains string   `json:"path_contains,omitempty"`
	Detectors    []string `json:"detectors,omitempty"`
	Auto         bool     `json:"auto,omitempty"`
}

// Start: proxy-poc MCP 서버를 addr에서 기동(StreamableHTTP, 블로킹).
func Start(addr string) {
	server := mcp.NewServer(&mcp.Implementation{Name: "proxy-poc", Version: "0.2.0"}, nil)

	// ── 조회 도구 ──────────────────────────────────────────────

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_endpoints",
		Description: "List the attack surface the proxy has captured: host, normalized path, HTTP methods, parameter names, and hit count.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(endpoints.Snapshot()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_endpoint",
		Description: "Get details for one captured endpoint by host and normalized path (e.g. path \"/user/{id}\"). Returns methods, parameters (name+location), auth-required, risk verdict, and hit count.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getEndpointArgs) (*mcp.CallToolResult, any, error) {
		if n, ok := endpoints.Find(args.Host, args.Path); ok {
			return jsonResult(n), nil, nil
		}
		return textResult(fmt.Sprintf("not found: host=%q path=%q", args.Host, args.Path)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "recent_requests",
		Description: "Return the most recent requests that passed through the proxy (sensitive values already masked). Optional 'limit' (default 20).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args limitArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit <= 0 {
			limit = 20
		}
		return jsonResult(traffic.Recent(limit)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "stats",
		Description: "Summary of the current diagnosis session: number of endpoints, distinct hosts, total hits, recent-traffic buffer size, and the active scope.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		sm := endpoints.Summary()
		return jsonResult(map[string]any{
			"endpoints":     sm.Endpoints,
			"hosts":         sm.Hosts,
			"total_hits":    sm.Hits,
			"recent_buffer": traffic.Count(),
			"scope":         scope.HostsSnapshot(),
		}), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_scope",
		Description: "Get the current diagnosis scope (whitelisted hosts). Only these pass through the proxy; everything else is blocked.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(scope.Snapshot()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_auth",
		Description: "Show the auth-crawling injection (FR-2.5): which cookie names and header names are injected into in-scope requests. Values are masked (names only).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(auth.Snapshot()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_identities",
		Description: "List registered diagnosis identities (FR-3.6) used by the multi-identity/IDOR detector to cross-request endpoints. Names only (anon is always included); credential values are not exposed.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(auth.IdentityNames()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_rules",
		Description: "List the pre-send Rule stage: deterministic rules that block dangerous/destructive in-scope requests (logout, delete, admin, payment) before they are forwarded, to protect availability.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(rules.Snapshot()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "llm_decisions",
		Description: "List LLM stage decisions: for requests the rules deferred to the LLM, the token-minimized input and the verdict (allow/block, reason, provider). Basis for rule-promotion analysis.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(llm.Decisions()), nil, nil
	})

	// ── 자동화 진단 (§5.3) ─────────────────────────────────────

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_payloads",
		Description: "Show the payload/wordlist set (FR-3.7): version, XSS payloads, and Korean sensitive-info pattern names used by detectors.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(payload.Info()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_detectors",
		Description: "List available diagnosis detectors (id, name, destructive) for selection in run_scan (FR-3.1).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(detector.Catalog()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_projects",
		Description: "List diagnosis projects (§5.1, §3 Project): id, name, main URL, scope, selected schemes, timestamps.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(project.List()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_active_project",
		Description: "Get the active project (§5.1). Its scope + selected schemes are what the live engine is currently configured with.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		p, _ := project.Active()
		return jsonResult(p), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "create_project",
		Description: "Create a diagnosis project (§5.1, §3 Project) with name/main_url/scope/schemes. Set activate=true to make it active and apply its scope + schemes to the live engine.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args createProjectArgs) (*mcp.CallToolResult, any, error) {
		u, ok := authz("project:create", args.Name)
		if !ok {
			return textResult("권한 없음: project:create (" + string(u.Role) + ")"), nil, nil
		}
		mainURL := args.MainURL
		if mainURL == "" && len(args.Scope) > 0 {
			mainURL = "https://" + args.Scope[0]
		}
		p := project.Create(project.Project{Owner: u.ID, Name: args.Name, MainURL: mainURL, Scope: args.Scope, Schemes: args.Schemes})
		audit.Record(u.Name, string(u.Role), "project:create", p.ID, "ok", p.Name)
		if args.Activate {
			project.SetActive(p.ID)
			applyProject(p)
			audit.Record(u.Name, string(u.Role), "project:activate", p.ID, "ok", p.Name)
		}
		log.Printf("[MCP ] %s(%s) create_project %s (%s) activate=%v", u.Name, u.Role, p.ID, p.Name, args.Activate)
		return jsonResult(p), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "activate_project",
		Description: "Activate a project (§5.1): sets it active and re-configures the live engine's scope + selected schemes to match it.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args projectIDArgs) (*mcp.CallToolResult, any, error) {
		u, ok := authz("project:activate", args.ID)
		if !ok {
			return textResult("권한 없음: project:activate (" + string(u.Role) + ")"), nil, nil
		}
		if !project.SetActive(args.ID) {
			return textResult("not found: " + args.ID), nil, nil
		}
		p, _ := project.Get(args.ID)
		applyProject(p)
		audit.Record(u.Name, string(u.Role), "project:activate", p.ID, "ok", p.Name)
		log.Printf("[MCP ] %s(%s) activate_project %s (%s)", u.Name, u.Role, p.ID, p.Name)
		return jsonResult(p), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "export_project",
		Description: "Export a project (metadata + findings) to a native-format file with the user-defined extension (FR-1.6 DRM non-interference). Auth credentials are excluded (server-key bound). Standard xlsx export stays on-demand via export_report. Writes <name>.<ext> (default .cgpkg) unless 'path' given.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args exportProjectArgs) (*mcp.CallToolResult, any, error) {
		data, base, err := bundle.Export(args.ID)
		if err != nil {
			return textResult("export 실패: " + err.Error()), nil, nil
		}
		path := args.Path
		if path == "" {
			path = base + bundle.Ext()
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			return textResult("파일 쓰기 실패: " + err.Error()), nil, nil
		}
		return textResult(fmt.Sprintf("wrote %s (%d bytes) — DRM 비간섭 네이티브 포맷", path, len(data))), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "import_project",
		Description: "Import a native-format project bundle file (FR-1.6) into a new project with its findings — for sharing a project between analyst PCs without DRM breakage.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args importProjectArgs) (*mcp.CallToolResult, any, error) {
		u, ok := authz("project:create", args.Path)
		if !ok {
			return textResult("권한 없음: project:create (" + string(u.Role) + ")"), nil, nil
		}
		data, err := os.ReadFile(args.Path)
		if err != nil {
			return textResult("파일 읽기 실패: " + err.Error()), nil, nil
		}
		np, n, err := bundle.Import(data)
		if err != nil {
			return textResult("가져오기 실패: " + err.Error()), nil, nil
		}
		audit.Record(u.Name, string(u.Role), "project:import", np.ID, "ok", np.Name)
		return jsonResult(map[string]any{"project": np, "findings": n}), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_project_credentials",
		Description: "Show a project's stored auth credentials as a MASKED summary (§5.1 FR-1.4): cookie/header/identity NAMES only — values are encrypted at rest (AES-256-GCM) and never returned.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args projectIDArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(project.CredentialSummary(args.ID)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "set_project_credentials",
		Description: "Set a project's auth credentials (cookies/headers/identities), stored ENCRYPTED at rest (§5.1 FR-1.4; leader-only). On the active project they are injected into the live auth-crawling (FR-2.5) and multi-identity (FR-3.6) engine. Values are never persisted or returned in plaintext.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args setCredsArgs) (*mcp.CallToolResult, any, error) {
		u, ok := authz("project:credentials", args.ID)
		if !ok {
			return textResult("권한 없음: project:credentials (" + string(u.Role) + ")"), nil, nil
		}
		creds := project.Credentials{Cookies: args.Cookies, Headers: args.Headers, Identities: args.Identities}
		if err := project.SetCredentials(args.ID, creds); err != nil {
			return textResult("저장 실패: " + err.Error()), nil, nil
		}
		if ap, ok := project.Active(); ok && ap.ID == args.ID {
			applyCredentials(args.ID)
		}
		audit.Record(u.Name, string(u.Role), "project:credentials", args.ID, "ok", "encrypted")
		return jsonResult(project.CredentialSummary(args.ID)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "start_tenant_proxy",
		Description: "Start a dedicated proxy instance for a project on its own port (§5.1 FR-1.1 multi-tenancy). It enforces the project's own scope and captures its attack surface into an isolated endpoint tree — so multiple projects can be diagnosed concurrently without cross-contamination. The shared :8080 proxy is unaffected.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args projectIDArgs) (*mcp.CallToolResult, any, error) {
		info, err := tenant.Start(args.ID)
		if err != nil {
			return textResult("시작 실패: " + err.Error()), nil, nil
		}
		return jsonResult(info), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "stop_tenant_proxy",
		Description: "Stop a project's dedicated proxy instance (§5.1 multi-tenancy).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args projectIDArgs) (*mcp.CallToolResult, any, error) {
		return textResult(fmt.Sprintf("stopped %s: %v", args.ID, tenant.Stop(args.ID))), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_tenant_proxies",
		Description: "List running per-project proxy instances (§5.1 multi-tenancy): project id, port, scope, captured endpoint count.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(tenant.List()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "tenant_endpoints",
		Description: "Show the isolated attack-surface tree captured by a project's dedicated proxy (§5.1 multi-tenancy) — separate from the shared :8080 proxy's tree.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args projectIDArgs) (*mcp.CallToolResult, any, error) {
		eps, ok := tenant.Endpoints(args.ID)
		if !ok {
			return textResult("실행 중 테넌트 아님: " + args.ID), nil, nil
		}
		return jsonResult(eps), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "add_project_member",
		Description: "Grant a user access to a project (§5.1 FR-1.4 per-project ACL; leader-only). Analysts can only see/activate projects they own or are members of; leaders have full access.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args memberArgs) (*mcp.CallToolResult, any, error) {
		u, ok := authz("project:members", args.ID)
		if !ok {
			return textResult("권한 없음: project:members (" + string(u.Role) + ")"), nil, nil
		}
		if !project.AddMember(args.ID, args.UserID) {
			return textResult("not found: " + args.ID), nil, nil
		}
		audit.Record(u.Name, string(u.Role), "project:member_add", args.ID, "ok", args.UserID)
		p, _ := project.Get(args.ID)
		return jsonResult(p), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "remove_project_member",
		Description: "Revoke a user's access to a project (§5.1 FR-1.4 ACL; leader-only).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args memberArgs) (*mcp.CallToolResult, any, error) {
		u, ok := authz("project:members", args.ID)
		if !ok {
			return textResult("권한 없음: project:members (" + string(u.Role) + ")"), nil, nil
		}
		project.RemoveMember(args.ID, args.UserID)
		audit.Record(u.Name, string(u.Role), "project:member_remove", args.ID, "ok", args.UserID)
		p, _ := project.Get(args.ID)
		return jsonResult(p), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "whoami",
		Description: "Current user + role and allowed actions (§5.1 FR-1.4).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		u, _ := user.Current()
		return jsonResult(map[string]any{"user": u, "can": user.Actions(u.Role)}), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_users",
		Description: "List users and roles (§5.1 FR-1.4): leader / analyst.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(user.List()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_audit",
		Description: "Audit log (§5.1 FR-1.5): who/when/what/result for every change (project create/activate, user switch, permission denials).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(audit.List()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_schemes",
		Description: "List the regulatory check schemes/tabs in the check-item table (§6): 주요정보통신기반시설 / 전자금융 / 모바일.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(checklist.Schemes()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_selected_schemes",
		Description: "Show the project's selected check schemes/tabs (§3, §6). Coverage and finding-tagging are scoped to these; empty selection means all schemes.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(checklist.Selected()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "set_selected_schemes",
		Description: "Set the project's selected check schemes/tabs (§3, §6) at runtime, scoping coverage and finding-tagging. Pass an empty list to select all.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args setSchemesArgs) (*mcp.CallToolResult, any, error) {
		schemes := make([]checklist.Scheme, 0, len(args.Schemes))
		for _, s := range args.Schemes {
			schemes = append(schemes, checklist.Scheme(s))
		}
		checklist.SetSelected(schemes)
		log.Printf("[MCP ] set_selected_schemes(%v)", args.Schemes)
		return jsonResult(checklist.Selected()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_checkitems",
		Description: "List check items (§6, 3-layer): each scheme-specific item with its VulnDef (name/CWE) and mapped detectors. Optional 'scheme' filters to one tab.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args schemeArgs) (*mcp.CallToolResult, any, error) {
		items := checklist.Current().CheckItems
		if args.Scheme != "" {
			items = checklist.CheckItemsByScheme(checklist.Scheme(args.Scheme))
		}
		// 항목에 2층 VulnDef·1층 detector 를 펼쳐서 함께 반환(3계층 한눈에).
		type row struct {
			checklist.CheckItem
			VulnName  string   `json:"vuln_name"`
			CWE       string   `json:"cwe,omitempty"`
			Detectors []string `json:"detectors"`
		}
		out := make([]row, 0, len(items))
		for _, c := range items {
			r := row{CheckItem: c, Detectors: checklist.DetectorsFor(c.ID)}
			if v, ok := checklist.VulnByID(c.Vuln); ok {
				r.VulnName, r.CWE = v.Name, v.CWE
			}
			out = append(out, r)
		}
		return jsonResult(out), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "coverage_report",
		Description: "Per-scheme coverage of the check-item table (§6 ↔ §5.3): for each item, status is 취약 / 점검-이상없음 / 미점검 / 미지원(도구없음) / 미지원(수동), computed from available detectors, which have run across scan runs, and findings so far.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(coverage.Report()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "run_scan",
		Description: "Start automated diagnosis (§5.3, async — poll scan_status). Select targets ('hosts','path_contains'), 'auto' to keep only attack-surface-rich endpoints (FR-3.9), or a saved 'profile' (FR-3.9); pick detectors ('detectors' ids); empty = all (FR-3.1). Destructive detectors skipped unless 'allow_destructive' (FR-3.2). 'llm_review' to LLM-triage findings (FR-3.3). Returns a running ScanRun.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args runScanArgs) (*mcp.CallToolResult, any, error) {
		hosts, pathContains, dets, auto := args.Hosts, args.PathContains, args.Detectors, args.Auto
		if args.Profile != "" { // 프로파일 적용 (FR-3.9)
			if p, ok := profile.Get(args.Profile); ok {
				hosts, pathContains, dets, auto = p.Hosts, p.PathContains, p.Detectors, p.Auto
			}
		}
		targets := filterTargets(endpoints.Targets(), hosts, pathContains)
		if auto { // 공격면 넓은 대상만
			targets = autoTargets(targets)
		}
		sr := scanengine.Start(targets, detector.Select(dets), scanengine.Options{AllowDestructive: args.AllowDestructive, LLMReview: args.LLMReview})
		return jsonResult(sr), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "save_profile",
		Description: "Save a named target profile (FR-3.9): reusable target filter (hosts/path_contains/auto) + detector selection, for later run_scan via 'profile'.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args saveProfileArgs) (*mcp.CallToolResult, any, error) {
		profile.Save(profile.Profile{Name: args.Name, Hosts: args.Hosts, PathContains: args.PathContains, Detectors: args.Detectors, Auto: args.Auto})
		return textResult("saved profile: " + args.Name), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_profiles",
		Description: "List saved target profiles (FR-3.9).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(profile.List()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_status",
		Description: "Get a scan's live status and progress (FR-3.8): status (진행/일시정지/완료/중단), done/total units, findings.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args scanIDArgs) (*mcp.CallToolResult, any, error) {
		if sr, ok := scanengine.Status(args.ID); ok {
			return jsonResult(sr), nil, nil
		}
		return textResult("not found: " + args.ID), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "pause_scan",
		Description: "Pause a running scan (FR-3.8).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args scanIDArgs) (*mcp.CallToolResult, any, error) {
		return textResult(fmt.Sprintf("pause %s: %v", args.ID, scanengine.Pause(args.ID))), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "resume_scan",
		Description: "Resume a paused scan (FR-3.8).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args scanIDArgs) (*mcp.CallToolResult, any, error) {
		return textResult(fmt.Sprintf("resume %s: %v", args.ID, scanengine.Resume(args.ID))), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "cancel_scan",
		Description: "Cancel (stop) a scan (FR-3.8).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args scanIDArgs) (*mcp.CallToolResult, any, error) {
		return textResult(fmt.Sprintf("cancel %s: %v", args.ID, scanengine.Cancel(args.ID))), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "kill_switch",
		Description: "Emergency stop: cancel ALL running scans immediately (guardrail FR-3.2).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return textResult(fmt.Sprintf("killed %d running scan(s)", scanengine.KillAll())), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "set_safe_mode",
		Description: "Toggle safe mode (guardrail FR-3.2). When ON, all scans force-exclude destructive detectors regardless of allow_destructive, and the request rate is throttled harder to protect target availability.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args safeModeArgs) (*mcp.CallToolResult, any, error) {
		scanengine.SetSafeMode(args.On)
		log.Printf("[MCP ] set_safe_mode(on=%v)", args.On)
		return textResult(fmt.Sprintf("safe_mode=%v", scanengine.SafeMode())), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_safe_mode",
		Description: "Report whether safe mode (guardrail FR-3.2) is currently ON.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return textResult(fmt.Sprintf("safe_mode=%v", scanengine.SafeMode())), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_findings",
		Description: "List diagnosis findings (§3 Finding): vulnerability, severity, endpoint, method, param, detection kind, confidence, and masked evidence.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(finding.Snapshot()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "reverify",
		Description: "Reverification (§5.5): replay vulnerable findings and re-evaluate whether each is fixed. Verdict per finding: 조치완료(fixed)/미조치(open)/미확인(manual). Optional 'scan_run' limits to one ScanRun's findings; else all. Only replays targeted findings, not a full re-scan (FR-5.1).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args reverifyArgs) (*mcp.CallToolResult, any, error) {
		items := finding.Snapshot()
		source := "all"
		if args.ScanRun != "" {
			items = finding.ByScanRun(args.ScanRun)
			source = args.ScanRun
		}
		return jsonResult(reverify.Reverify(ctx, items, source)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_reverify",
		Description: "List past reverification runs (§5.5): each with fixed/open/unknown counts and per-finding verdicts.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(reverify.Runs()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_diff",
		Description: "Attack-surface diff between two ScanRuns (§5.5 FR-5.4): findings present only in 'to' (신규/new) vs only in 'from' (소멸/gone), plus common count.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args diffArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(reverify.DiffRuns(args.From, args.To)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "export_report",
		Description: "Export the findings 도출리스트 as an .xlsx file (§5.4, FR-4.1): the fixed 11-column form (NO/대상명/메인 URL/발견 취약점/발견 경로/발견된 URL/파라미터/설명/취약점 건수/사용 구문/비고). Writes 도출리스트.xlsx in the working directory. The web GUI also serves it at /report.xlsx.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		n, err := report.WriteExcel(report.Filename())
		if err != nil {
			return textResult("export 실패: " + err.Error()), nil, nil
		}
		return textResult(fmt.Sprintf("wrote %s (%d rows) — %s", report.Filename(), n, report.Summary())), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "export_coverage",
		Description: "Export the 점검결과표/coverage report as an .xlsx (§5.4, FR-4.3): ALL check items per scheme with result 양호|취약|미점검 (not just vulnerabilities), one sheet per scheme + a summary sheet. Writes 점검결과표.xlsx; web GUI serves it at /coverage.xlsx.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		n, err := report.WriteCoverageExcel(report.CoverageFilename())
		if err != nil {
			return textResult("export 실패: " + err.Error()), nil, nil
		}
		return textResult(fmt.Sprintf("wrote %s (%d items)", report.CoverageFilename(), n)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "rule_candidates",
		Description: "Rule-promotion candidates (§5.6, FR-6.2/6.3): clusters the LLM decision log by normalized signature and proposes deterministic, high-consistency patterns for promotion to rules. Each candidate carries a draft rule, hit count, consistency %, estimated savings, and false-positive warnings. Proposal only — analyst approval required (HITL).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(advisor.Candidates()), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "set_finding_status",
		Description: "Transition a finding's review status (FR-4.4: 신규→검토중→확정|오탐|보류→보고) with optimistic concurrency (FR-1.3). Pass the 'version' you last read; if someone else edited it first the call reports a conflict and returns the current finding to re-read. Records reviewer + audit.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args findingStatusArgs) (*mcp.CallToolResult, any, error) {
		u, ok := authz("finding:confirm", args.ID)
		if !ok {
			return textResult("권한 없음: finding:confirm (" + string(u.Role) + ")"), nil, nil
		}
		f, err := finding.SetStatus(args.ID, args.Status, args.Version, u.Name)
		switch err {
		case finding.ErrConflict:
			audit.Record(u.Name, string(u.Role), "finding:status", args.ID, "conflict", "")
			return jsonResult(map[string]any{"error": "conflict", "current": f}), nil, nil
		case finding.ErrBadTransition:
			return textResult(fmt.Sprintf("허용되지 않은 전이: %s→%s", f.Status, args.Status)), nil, nil
		case finding.ErrNotFound:
			return textResult("not found: " + args.ID), nil, nil
		case nil:
			audit.Record(u.Name, string(u.Role), "finding:status", args.ID, "ok", f.Status)
			return jsonResult(f), nil, nil
		default:
			return textResult(err.Error()), nil, nil
		}
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_scanruns",
		Description: "List scan runs (§3 ScanRun): each automated-diagnosis execution with its detectors, skipped (guardrailed) detectors, and finding count.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		return jsonResult(scanengine.Runs()), nil, nil
	})

	// ── 제어 도구 ──────────────────────────────────────────────

	mcp.AddTool(server, &mcp.Tool{
		Name:        "add_scope_host",
		Description: "Add a host to the diagnosis scope whitelist at runtime so the proxy starts allowing traffic to it. Demonstrates orchestration-layer control of the live proxy.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args hostArgs) (*mcp.CallToolResult, any, error) {
		added := scope.Add(args.Host)
		verb := "already in scope"
		if added {
			verb = "added"
		}
		log.Printf("[MCP ] add_scope_host(%q) added=%v", args.Host, added)
		return textResult(fmt.Sprintf("%s: %q; scope=%v", verb, args.Host, scope.HostsSnapshot())), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "remove_scope_host",
		Description: "Remove a host from the diagnosis scope whitelist at runtime so the proxy starts blocking it again.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args hostArgs) (*mcp.CallToolResult, any, error) {
		removed := scope.Remove(args.Host)
		verb := "not in scope"
		if removed {
			verb = "removed"
		}
		log.Printf("[MCP ] remove_scope_host(%q) removed=%v", args.Host, removed)
		return textResult(fmt.Sprintf("%s: %q; scope=%v", verb, args.Host, scope.HostsSnapshot())), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "proxy_status",
		Description: "Status of the shared :8080 proxy (issue #5): listen address, whether endpoint capture is on, scope host count, captured-request count since boot, and the captured attack-surface size (endpoints/hosts).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
		sm := endpoints.Summary()
		return jsonResult(map[string]any{
			"listen":            proxyengine.ListenAddr(),
			"capturing":         proxyengine.CaptureEnabled(),
			"scope_hosts":       len(scope.HostsSnapshot()),
			"captured_requests": proxyengine.CapturedCount(),
			"endpoints":         sm.Endpoints,
			"hosts":             sm.Hosts,
		}), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "set_capture",
		Description: "Turn the shared :8080 proxy's endpoint capture on/off (leader-only, audited). The proxy process, scope enforcement, auth injection and judgment pipeline are unaffected — only attack-surface recording pauses/resumes. Tenant proxies are not affected.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args captureArgs) (*mcp.CallToolResult, any, error) {
		u, ok := authz("proxy:control", "capture")
		if !ok {
			return textResult("권한 없음: proxy:control (" + string(u.Role) + ")"), nil, nil
		}
		proxyengine.SetCapture(args.On)
		audit.Record(u.Name, string(u.Role), "proxy:control", "capture", "ok", fmt.Sprintf("capture=%v", args.On))
		log.Printf("[MCP ] %s(%s) set_capture(on=%v)", u.Name, u.Role, args.On)
		return textResult(fmt.Sprintf("capturing=%v", proxyengine.CaptureEnabled())), nil, nil
	})

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	log.Printf("MCP 서버 시작: http://%s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Printf("MCP 서버 종료: %v", err)
	}
}

// autoTargets — 공격면 넓은(파라미터/인증/위험판단) 대상만 (FR-3.9 자동선정).
func autoTargets(all []endpoints.Target) []endpoints.Target {
	var out []endpoints.Target
	for _, t := range all {
		if t.Interesting() {
			out = append(out, t)
		}
	}
	return out
}

// filterTargets — 호스트 목록 + 경로 부분일치로 스캔 대상 필터 (FR-3.1). 둘 다 비면 전체.
func filterTargets(all []endpoints.Target, hosts []string, pathContains string) []endpoints.Target {
	if len(hosts) == 0 && pathContains == "" {
		return all
	}
	hostSet := map[string]bool{}
	for _, h := range hosts {
		hostSet[strings.ToLower(h)] = true
	}
	var out []endpoints.Target
	for _, t := range all {
		if len(hostSet) > 0 && !hostSet[strings.ToLower(t.Host)] {
			continue
		}
		if pathContains != "" && !strings.Contains(t.Path, pathContains) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// authz — 현재 사용자가 action 권한이 있는지. 없으면 감사기록 후 false (§5.1 FR-1.4).
func authz(action, target string) (user.User, bool) {
	u, _ := user.Current()
	if !user.Can(u.Role, action) {
		audit.Record(u.Name, string(u.Role), action, target, "denied", "권한 없음")
		return u, false
	}
	return u, true
}

// applyProject — 활성 프로젝트의 scope·선택 스킴·(암호화)인증정보를 라이브 엔진에 반영 (§5.1).
func applyProject(p project.Project) {
	scope.Configure(p.Scope, p.AllowPaths, p.ExcludePaths)
	schemes := make([]checklist.Scheme, 0, len(p.Schemes))
	for _, s := range p.Schemes {
		schemes = append(schemes, checklist.Scheme(s))
	}
	checklist.SetSelected(schemes)
	applyCredentials(p.ID)
}

// applyCredentials — 프로젝트 인증정보를 복호화해 auth 엔진에 주입 (§5.1 FR-1.4 / FR-2.5 / FR-3.6).
func applyCredentials(pid string) {
	cfg, ids, ok := project.CredsToAuth(pid)
	if !ok {
		auth.Set(auth.Config{})
		auth.SetIdentities(nil)
		return
	}
	auth.Set(cfg)
	auth.SetIdentities(ids)
}

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func jsonResult(v any) *mcp.CallToolResult {
	data, _ := json.MarshalIndent(v, "", "  ")
	return textResult(string(data))
}
