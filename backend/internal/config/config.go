// Package config — 설정 파일 로드 (문서 §4의 계층 설정).
// 성격이 다른 설정을 파일로 분리한다:
//
//	· Local  (local.config.yaml)   — PC마다 다름, 공유 금지. 포트 등 (추후 도구 경로·API 키).
//	· Project(project.config.yaml) — 공유/버전관리. 스코프·룰셋.
//
// 파일이 없으면 기본값으로 생성해 템플릿을 남긴다.
package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"

	"proxypoc/internal/auth"
	"proxypoc/internal/payload"
	"proxypoc/internal/rules"
)

// LLM — LLM 프로바이더 설정. API 키는 PC 전용이므로 로컬 설정에 둔다(§4).
type LLM struct {
	Provider string `yaml:"provider"` // mock | ollama | anthropic
	Model    string `yaml:"model"`    // 예: ollama "llama3.2"
	Endpoint string `yaml:"endpoint"` // 예: ollama "http://127.0.0.1:11434"
	APIKey   string `yaml:"api_key"`  // anthropic 등 외부 API용
}

// Local — PC마다 다른 설정 (서버 미동기). 문서 §4 로컬 설정.
type Local struct {
	ProxyAddr    string            `yaml:"proxy_addr"`    // 프록시 리슨 주소 (예: ":8080")
	MCPAddr      string            `yaml:"mcp_addr"`      // MCP 서버 주소 (예: "127.0.0.1:8765")
	WebAddr      string            `yaml:"web_addr"`      // 읽기전용 웹 GUI 주소 (예: "127.0.0.1:8090")
	LLM          LLM               `yaml:"llm"`           // LLM 스테이지 프로바이더
	Tools        map[string]string `yaml:"tools"`         // 외부 도구 실행 경로 (FR-3.4; 비면 PATH)
	SafeMode     bool              `yaml:"safe_mode"`     // 안전모드 기본값 (FR-3.2): 파괴성 강제제외 + 요청간격 강화
	AuthDisabled bool              `yaml:"auth_disabled"` // 개발용: 로그인 게이트 우회(항상 리더). 운영 금지.
	ArtifactExt  string            `yaml:"artifact_ext"`  // 산출물 네이티브 확장자 (FR-1.6 DRM 비간섭). 예: .cgpkg
	RetentionDays int              `yaml:"retention_days"` // 휴지통 프로젝트 자동 영구삭제 보존기간(일). 기본 30 (이슈 #15)
}

// Project — 공유/프로젝트 설정 (서버 버전관리). 문서 §4.
// (실제 제품에선 기본 룰셋=공유 계층, 스코프=프로젝트 계층으로 더 나뉨)
type Project struct {
	Scope        []string               `yaml:"scope"`         // 진단 대상 호스트 화이트리스트
	Schemes      []string               `yaml:"schemes"`       // 선택된 점검 스킴/탭 (§3, §6). 비면 전체
	AllowPaths   []string               `yaml:"allow_paths"`   // 경로 허용(정규식). 비면 전체 허용 (FR-2.1)
	ExcludePaths []string               `yaml:"exclude_paths"` // 경로 제외(정규식). 허용보다 우선 (FR-2.1)
	ReconAllow   []string               `yaml:"recon_allow"`   // recon(GET/HEAD) 허용 경로(정규식). guardrail보다 우선 (접근통제 점검)
	Stages       []string               `yaml:"stages"`        // 판단 스테이지 구성/순서 (FR-2.2): rule, llm
	Rules        []rules.Rule           `yaml:"rules"`         // 전송 전 Rule 스테이지 룰셋
	Auth         auth.Config            `yaml:"auth"`          // 인증 크롤링 주입정보 (FR-2.5; 제품은 서버 암호화)
	Login        auth.LoginSeq          `yaml:"login"`         // 세션 만료 시 자동 재로그인 절차 (FR-2.5 세션 지속성)
	Identities   map[string]auth.Config `yaml:"identities"`    // 다중 신원 진단용 신원들 (FR-3.6)
	Payloads     Payloads               `yaml:"payloads"`      // 페이로드/워드리스트 확장 (FR-3.7)
}

// Payloads — 페이로드셋 확장 (공유설정, FR-3.7). 비면 내장 기본셋만 사용.
type Payloads struct {
	XSS               []string          `yaml:"xss"`
	SensitivePatterns []payload.Pattern `yaml:"sensitive_patterns"`
}

func defaultLocal() Local {
	return Local{
		ProxyAddr:   ":8080",
		MCPAddr:     "127.0.0.1:8765",
		WebAddr:     "127.0.0.1:8090",
		LLM:         LLM{Provider: "mock", Endpoint: "http://127.0.0.1:11434", Model: "llama3.2"},
		Tools:         map[string]string{}, // 예: {sslscan: "C:/tools/sslscan.exe"}
		ArtifactExt:   ".cgpkg",            // DRM 비간섭 사용자 지정 확장자 (FR-1.6)
		RetentionDays: 30,                  // 휴지통 보존기간 기본 30일 (이슈 #15)
	}
}

func defaultProject() Project {
	return Project{
		Scope:        []string{"example.com", "httpbin.org"},
		AllowPaths:   []string{},
		ExcludePaths: []string{},
		Stages:       []string{"rule", "llm"},
		Rules:        rules.Defaults(),
		Auth:         auth.Config{Cookies: map[string]string{}, Headers: map[string]string{}},
		Identities:   map[string]auth.Config{},
	}
}

// LoadLocal — 로컬 설정 로드. 없으면 기본값으로 파일 생성 후 반환.
func LoadLocal(path string) Local {
	cfg := defaultLocal()
	loadOrCreate(path, &cfg, "# 로컬 설정 — 이 PC 전용, 공유/커밋 금지\n")
	return cfg
}

// LoadProject — 프로젝트/공유 설정 로드. 없으면 기본값으로 파일 생성 후 반환.
func LoadProject(path string) Project {
	cfg := defaultProject()
	loadOrCreate(path, &cfg, "# 프로젝트/공유 설정 — 스코프와 Rule 스테이지 룰셋\n")
	return cfg
}

// 파일이 있으면 out에 언마샬, 없으면 out(기본값)을 파일로 써 둔다.
func loadOrCreate(path string, out any, header string) {
	data, err := os.ReadFile(path)
	if err != nil {
		b, mErr := yaml.Marshal(out)
		if mErr == nil {
			_ = os.WriteFile(path, append([]byte(header), b...), 0644)
			log.Printf("설정 파일 생성: %s (기본값)", path)
		}
		return
	}
	if err := yaml.Unmarshal(data, out); err != nil {
		log.Printf("설정 파싱 실패(%s) — 기본값 사용: %v", path, err)
		return
	}
	log.Printf("설정 로드: %s", path)
}
