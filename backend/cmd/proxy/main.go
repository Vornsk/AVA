// Command proxy — proxy-poc 진입점.
// 설정 로드 → CA 준비 → (cert 명령 처리) → goproxy 조립 → MCP 기동 → 서빙.
// cert-manager 명령 (프록시 안 띄우고 실행 후 종료):
//
//	-cert-status    CA 신뢰 상태 확인 (FR-2.6)
//	-cert-install   CA 신뢰 저장소에 설치 (FR-2.7, 멱등)
//	-cert-uninstall CA 신뢰 저장소에서 제거 (FR-2.9)
//	-cert-verify    프록시 경유 인터셉트 검증 (FR-2.9; 프록시 실행 중이어야 함)
package main

import (
	"flag"
	"log"
	"net/http"
	"sort"
	"strconv"

	"proxypoc/internal/audit"
	"proxypoc/internal/auth"
	"proxypoc/internal/ca"
	"proxypoc/internal/checklist"
	"proxypoc/internal/config"
	"proxypoc/internal/detector"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/finding"
	"proxypoc/internal/llm"
	"proxypoc/internal/mcpserver"
	"proxypoc/internal/payload"
	projects "proxypoc/internal/project"
	"proxypoc/internal/proxyengine"
	"proxypoc/internal/retention"
	"proxypoc/internal/rules"
	"proxypoc/internal/scanengine"
	"proxypoc/internal/scope"
	"proxypoc/internal/secret"
	"proxypoc/internal/tenant"
	"proxypoc/internal/user"
	"proxypoc/internal/webui"
)

func main() {
	certStatus := flag.Bool("cert-status", false, "CA 신뢰 상태 확인 후 종료")
	certInstall := flag.Bool("cert-install", false, "CA를 신뢰 저장소에 설치 후 종료")
	certUninstall := flag.Bool("cert-uninstall", false, "CA를 신뢰 저장소에서 제거 후 종료")
	certVerify := flag.Bool("cert-verify", false, "프록시 경유 인터셉트 검증 후 종료(프록시 실행중이어야 함)")
	flag.Parse()

	// 설정 로드 (없으면 기본값으로 파일 생성) — 하드코딩 대신 파일 기반 (문서 §4)
	local := config.LoadLocal("local.config.yaml")

	// 전용 CA 준비(없으면 생성)
	if err := ca.Ensure(); err != nil {
		log.Fatalf("CA 준비 실패: %v", err)
	}

	// cert-manager 명령이면 처리 후 종료 (프록시 안 띄움)
	if handleCert(*certStatus, *certInstall, *certUninstall, *certVerify, local.ProxyAddr) {
		return
	}

	project := config.LoadProject("project.config.yaml")
	scope.Configure(project.Scope, project.AllowPaths, project.ExcludePaths)
	rules.Load(project.Rules)
	rules.SetReconAllow(project.ReconAllow) // recon 허용 경로를 guardrail 앞에 (접근통제 점검)
	rules.LoadAdopted()                     // HITL로 승인·채택된 룰 복원 (rules.adopted.json)
	// 판단 프롬프트 정책의 기본값 (이슈 #53). 프로젝트가 자기 값을 가지면 활성화 시 덮어쓴다.
	basePolicy, policyErr := llm.ResolvePolicy(project.JudgePrompt, project.JudgePromptCustom)
	if policyErr != nil {
		log.Printf("판단 프롬프트 설정 경고: %v", policyErr)
	}
	llm.SetBasePolicy(basePolicy)
	log.Printf("판단 프롬프트(기본): %s", basePolicy)
	// 판단 불능 시 정책 (이슈 #56). 기본 allow — 대상 가용성 우선(1원칙).
	if project.JudgeOnError != "" && !llm.SetFailurePolicy(project.JudgeOnError) {
		log.Printf("경고: judge_on_error=%q 는 allow|block 이 아니다 — 기본 allow 유지", project.JudgeOnError)
	}
	log.Printf("판단 불능 시 정책: %s", llm.FailurePolicy())
	auth.Set(project.Auth)
	auth.SetIdentities(toIdentities(project.Identities)) // 다중 신원 (FR-3.6)
	auth.SetLogin(project.Login)                         // 세션 만료 시 자동 재로그인 (FR-2.5)
	detector.SetToolPaths(local.Tools)                   // 외부 도구 경로 (FR-3.4)
	payload.SetXSS(project.Payloads.XSS)                 // 페이로드셋 확장 (FR-3.7)
	payload.AddSensitive(project.Payloads.SensitivePatterns)
	scanengine.SetSafeMode(local.SafeMode) // 안전모드 기본값 (FR-3.2)
	if local.SafeMode {
		log.Printf("안전모드 ON (FR-3.2): 파괴성 강제제외 + 요청간격 강화")
	}

	// 점검항목표 (§6, 3계층). 파일 없으면 기본표 생성. detector 매핑 무결성 검증.
	checklist.LoadOrCreate("checklist.config.yaml")
	avail := map[string]bool{}
	for _, d := range detector.Catalog() {
		avail[d.ID] = true
	}
	if issues := checklist.Validate(avail); len(issues) > 0 {
		for _, is := range issues {
			log.Printf("점검항목표 경고: %s", is)
		}
	}
	// 프로젝트가 선택한 스킴/탭 적용 (§3, §6). 비면 전체.
	checklist.SetSelected(toSchemes(project.Schemes))
	if all := map[checklist.Scheme]bool{}; len(project.Schemes) > 0 {
		for _, s := range checklist.Schemes() {
			all[s] = true
		}
		for _, s := range project.Schemes {
			if !all[checklist.Scheme(s)] {
				log.Printf("점검항목표 경고: 선택 스킴 %q 가 항목표에 없음", s)
			}
		}
		log.Printf("선택 스킴(§6): %v", project.Schemes)
	}

	// 인증정보 암호화 마스터 키 (§5.1 FR-1.4). 없으면 생성.
	if err := secret.Init("secret.key"); err != nil {
		log.Printf("secret 초기화 실패(인증정보 암호화 비활성): %v", err)
	} else {
		log.Printf("인증정보 암호화 키 준비됨 (secret.key)")
	}

	// 사용자·역할 (§5.1 FR-1.4). 프로젝트보다 먼저 시드해 기본 프로젝트 소유자를 리더로 지정.
	user.Load()
	user.Seed()
	ownerID := ""
	if u, ok := user.Current(); ok {
		ownerID = u.ID
		log.Printf("현재 사용자: %s (%s)", u.Name, u.Role)
	}

	// 프로젝트 엔티티 (§5.1, §3 Project). 저장 파일 로드, 없으면 config 기반 기본 프로젝트 생성.
	projects.Load()
	if projects.Count() == 0 {
		name := "default"
		if len(project.Scope) > 0 {
			name = project.Scope[0]
		}
		p := projects.Create(projects.Project{
			Owner: ownerID, // 소유자=리더 (멤버 ACL, FR-1.4)
			Name:  name, MainURL: "https://" + name,
			Scope: project.Scope, AllowPaths: project.AllowPaths,
			ExcludePaths: project.ExcludePaths, Schemes: project.Schemes,
			JudgePrompt: project.JudgePrompt, JudgePromptCustom: project.JudgePromptCustom, // 이슈 #53
		})
		log.Printf("기본 프로젝트 생성: %s (%s, owner=%s)", p.ID, p.Name, ownerID)
	}
	if ap, ok := projects.Active(); ok {
		// 활성 프로젝트의 전역 상태(스코프·스킴·인증정보·판단 프롬프트) 전체 재적용.
		// webui.activateHandler 와 같은 함수를 써야 한다 — 예전엔 판단 프롬프트만 여기서
		// 다시 적용하고 스코프는 위 project.config.yaml(고정 설정) 값 그대로 남아있어서,
		// 재시작할 때마다 활성 프로젝트의 실제 대상 호스트가 스코프 밖으로 밀려나
		// 자동 크롤이 조용히 0건으로 끝나는 버그가 있었다.
		pol, err := webui.ApplyActiveProjectSettings(ap)
		if err != nil {
			log.Printf("판단 프롬프트 경고(%s): %v", ap.ID, err)
		}
		log.Printf("활성 프로젝트: %s (%s, 판단 프롬프트 %s, 스코프 %v)", ap.ID, ap.Name, pol, ap.Scope)
	}

	// 도출 항목·스캔 이력 복원 (재시작 시 유지).
	// 공격면(endpoints)은 프로젝트별이라(이슈 #65) 위 ApplyActiveProjectSettings 의
	// endpoints.SwitchProject 가 활성 프로젝트의 endpoints.<pid>.json 을 이미 로드했다.
	finding.Load()
	scanengine.Load() // 완료/중단 스캔 이력 (scanruns.json)
	if n := len(finding.Snapshot()); n > 0 {
		log.Printf("도출 항목 복원: %d건 (findings.json)", n)
	}
	if n := len(endpoints.Targets()); n > 0 {
		log.Printf("공격면 복원: %d개 엔드포인트 (활성 프로젝트 endpoints.<pid>.json)", n)
	}
	if n := len(scanengine.Runs()); n > 0 {
		log.Printf("스캔 이력 복원: %d건 (scanruns.json)", n)
	}

	// 휴지통 자동 영구삭제 스위퍼 (이슈 #15) — 기동 시 1회 + 6시간 주기.
	retention.StartSweeper(local.RetentionDays)

	// 판단 불능 상태 전이를 감사에 남긴다 (이슈 #56). fail-open 이 발동해도 화면·로그가
	// 멀쩡해 보이던 게 이 버그의 핵심이라, 상태가 바뀌는 순간을 증적으로 남긴다.
	// 요청마다가 아니라 전이 시점에만 불린다.
	llm.SetDegradeNotifier(func(degraded bool, h llm.Health) {
		if degraded {
			audit.Record("system", "system", "llm:degraded", h.Provider, "denied",
				"판단 불능 — 정책 "+h.Policy+" 로 흡수: "+h.Reason)
			log.Printf("[LLM ] ★ 판단 불능 진입 (정책 %s, 프로바이더 %s): %s", h.Policy, h.Provider, h.Reason)
			return
		}
		audit.Record("system", "system", "llm:recovered", h.Provider, "ok",
			"판단 복구 — 누적 불능 "+strconv.Itoa(h.Count)+"건")
		log.Printf("[LLM ] 판단 복구 (누적 불능 %d건)", h.Count)
	})

	// LLM 스테이지 프로바이더 (config 기반, 교체는 llm.New 한 곳에서)
	llm.SetProvider(llm.New(local.LLM.Provider, local.LLM.Model, local.LLM.Endpoint, local.LLM.APIKey))
	log.Printf("LLM 프로바이더: %s (model=%s)", local.LLM.Provider, local.LLM.Model)

	// CA 신뢰 상태 로그 (FR-2.6). 미신뢰면 -cert-install 안내.
	if trusted, _ := ca.IsTrusted(); trusted {
		log.Printf("CA 신뢰 상태: 설치됨(신뢰)")
	} else {
		log.Printf("CA 신뢰 상태: 미설치 — 브라우저 테스트하려면 `proxy-poc.exe -cert-install`")
	}

	proxy := proxyengine.New(project.Stages)
	proxyengine.SetListenAddr(local.ProxyAddr) // 공용 프록시 상태 조회용 (이슈 #5)
	tenant.SetStages(project.Stages)           // 테넌트 프록시도 같은 판단 스테이지 (§5.1 멀티테넌시)

	// MCP 서버를 별도 포트에서 기동 (프록시와 같은 프로세스 = 라이브 상태 공유)
	go mcpserver.Start(local.MCPAddr)

	// 웹 GUI (§5.1) — 같은 프로세스, 라이브 상태 공유
	webui.SetAuthDisabled(local.AuthDisabled)
	webui.SetArtifactExt(local.ArtifactExt)     // 산출물 네이티브 확장자 (FR-1.6)
	webui.SetRetentionDays(local.RetentionDays) // 휴지통 D-n 표시용 (이슈 #15)
	if local.AuthDisabled {
		log.Printf("⚠ 인증 비활성(개발 모드): 로그인 없이 리더로 동작 — 운영 배포 금지")
	}
	if local.WebAddr != "" {
		go func() { log.Fatal(webui.Serve(local.WebAddr)) }()
	}

	log.Printf("프록시 시작: %s  스코프=%v  스테이지=%v  룰=%d개  인증주입=%v  MCP=http://%s  Web=http://%s",
		local.ProxyAddr, scope.HostsSnapshot(), project.Stages, len(rules.Snapshot()), auth.Enabled(), local.MCPAddr, local.WebAddr)
	log.Fatal(http.ListenAndServe(local.ProxyAddr, proxy))
}

// toIdentities — config의 신원 맵을 이름순 []auth.Identity 로 변환 (FR-3.6).
func toIdentities(m map[string]auth.Config) []auth.Identity {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]auth.Identity, 0, len(names))
	for _, n := range names {
		out = append(out, auth.Identity{Name: n, Cookies: m[n].Cookies, Headers: m[n].Headers, Privileged: m[n].Admin})
	}
	return out
}

func toSchemes(ss []string) []checklist.Scheme {
	out := make([]checklist.Scheme, 0, len(ss))
	for _, s := range ss {
		out = append(out, checklist.Scheme(s))
	}
	return out
}

// handleCert — cert 플래그가 있으면 해당 작업 실행하고 true 반환(종료 신호).
func handleCert(status, install, uninstall, verify bool, proxyAddr string) bool {
	switch {
	case status:
		tp, _ := ca.Thumbprint()
		trusted, err := ca.IsTrusted()
		if err != nil {
			log.Fatalf("상태확인 실패: %v", err)
		}
		log.Printf("CA 지문(SHA-1): %s", tp)
		log.Printf("신뢰 상태: %v", trusted)
	case install:
		if err := ca.Install(); err != nil {
			log.Fatalf("%v", err)
		}
	case uninstall:
		if err := ca.Uninstall(); err != nil {
			log.Fatalf("%v", err)
		}
	case verify:
		if err := ca.Verify(proxyAddr, "https://example.com/"); err != nil {
			log.Fatalf("%v", err)
		}
	default:
		return false
	}
	return true
}
