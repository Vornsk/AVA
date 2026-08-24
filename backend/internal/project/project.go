// Package project — 프로젝트 엔티티·저장 (§5.1, §3 Project). 단계적 구현 1단계: 데이터 기반.
// 지금까지 전역 싱글턴(scope·선택 스킴 등)으로 흩어진 진단 컨텍스트를 하나의 Project 로 묶고,
// 파일 기반 저장소(FR-1.2)에 보관한다. 활성 프로젝트를 두어 이후 다중 프로젝트·전환을 수용한다.
// (권한·동시성·서버 REST 는 후속 단계 FR-1.3~1.5)
package project

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/secret"
)

// Project — 진단 프로젝트 (§3 Project). 인증정보는 서버 암호화 대상이라 여기선 ref/이름만(FR-1.4).
type Project struct {
	ID           string   `json:"id"`
	Owner        string   `json:"owner,omitempty"`   // 생성자 user id (§5.1 FR-1.4)
	Members      []string `json:"members,omitempty"` // 접근 허용 user id (프로젝트별 ACL, FR-1.4)
	Name         string   `json:"name"`              // 대상명
	MainURL      string   `json:"main_url"`          // 메인 URL
	Scope        []string `json:"scope"`             // 허용 도메인 화이트리스트
	AllowPaths   []string `json:"allow_paths,omitempty"`
	ExcludePaths []string `json:"exclude_paths,omitempty"`
	Schemes      []string `json:"schemes,omitempty"` // 선택된 탭 (§6)
	// 판단(LLM) 프롬프트 정책 (이슈 #53). 프로젝트 활성화 시 적용. 비면 기동 시 기본 정책.
	JudgePrompt       string `json:"judge_prompt,omitempty"`        // strict | balanced | permissive
	JudgePromptCustom string `json:"judge_prompt_custom,omitempty"` // 지정 시 프리셋보다 우선
	JudgeOnError      string `json:"judge_on_error,omitempty"`      // 판단 불능 시 allow(기본)|block (이슈 #56)
	Created           string `json:"created"`
	Modified          string `json:"modified"`
	DeletedAt         string `json:"deleted_at,omitempty"` // 소프트 삭제 시각(RFC3339). 빈 값=정상 (이슈 #14)
	// 인증정보는 암호화된 blob 으로만 저장(§5.1 FR-1.4). 평문은 파일/JSON 어디에도 없다.
	EncCreds string `json:"enc_creds,omitempty"`
}

// Credentials — 프로젝트 인증정보(암호화 대상). 인증 크롤링(FR-2.5)·다중신원(FR-3.6)에 주입.
type Credentials struct {
	Cookies    map[string]string        `json:"cookies,omitempty"`
	Headers    map[string]string        `json:"headers,omitempty"`
	Identities map[string]IdentityCreds `json:"identities,omitempty"`
}

// IdentityCreds — 신원별 세션 자격증명.
type IdentityCreds struct {
	Cookies map[string]string `json:"cookies,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Admin   bool              `json:"admin,omitempty"` // 고권한(관리자) 신원 — 수직 권한상승 점검 대조 기준 (FR-3.6)
}

// CredSummary — 인증정보 요약(마스킹). 값은 절대 노출하지 않고 키 이름·개수만.
type CredSummary struct {
	HasCreds   bool     `json:"has_creds"`
	Cookies    []string `json:"cookies,omitempty"` // 이름만
	Headers    []string `json:"headers,omitempty"` // 이름만
	Identities []string `json:"identities,omitempty"`
	Admins     []string `json:"admins,omitempty"` // 고권한(관리자) 신원 이름 — 수직 권한상승 대조 기준
}

const file = "projects.json"

var (
	mu       sync.Mutex
	store    []Project
	activeID string
	seq      int
)

type persisted struct {
	Projects []Project `json:"projects"`
	Active   string    `json:"active"`
}

// Load — 저장 파일에서 프로젝트 복원. 없으면 무시(빈 상태).
func Load() {
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}
	var p persisted
	if json.Unmarshal(data, &p) != nil {
		return
	}
	mu.Lock()
	store = p.Projects
	activeID = p.Active
	for _, pr := range store { // seq 를 최대 id 로 맞춤
		if n := idNum(pr.ID); n > seq {
			seq = n
		}
	}
	mu.Unlock()
}

func idNum(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "p-"))
	return n
}

func persist() { // 호출부가 mu 를 잡고 있어야 함
	data, _ := json.MarshalIndent(persisted{Projects: store, Active: activeID}, "", "  ")
	_ = os.WriteFile(file, data, 0644)
}

// Create — 새 프로젝트 저장. id·타임스탬프 부여. 첫 프로젝트는 자동 활성.
func Create(p Project) Project {
	mu.Lock()
	seq++
	p.ID = fmt.Sprintf("p-%d", seq)
	now := time.Now().Format("2006-01-02 15:04:05")
	p.Created, p.Modified = now, now
	store = append(store, p)
	if activeID == "" {
		activeID = p.ID
	}
	persist()
	mu.Unlock()
	return p
}

// List — 정상(휴지통 아닌) 프로젝트 (이슈 #14: 소프트 삭제된 것은 제외).
func List() []Project {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Project, 0, len(store))
	for _, p := range store {
		if p.DeletedAt == "" {
			out = append(out, p)
		}
	}
	return out
}

// Trash — 휴지통(소프트 삭제된) 프로젝트 (이슈 #14).
func Trash() []Project {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Project, 0)
	for _, p := range store {
		if p.DeletedAt != "" {
			out = append(out, p)
		}
	}
	return out
}

// Delete — 소프트 삭제(휴지통 이동, 이슈 #14). DeletedAt 설정.
// 활성 프로젝트는 삭제 불가(먼저 전환) · 미존재 · 이미 휴지통이면 false.
func Delete(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	for i := range store {
		if store[i].ID == id {
			if store[i].DeletedAt != "" || activeID == id {
				return false
			}
			store[i].DeletedAt = time.Now().UTC().Format(time.RFC3339)
			persist()
			return true
		}
	}
	return false
}

// Restore — 휴지통에서 복구(이슈 #14). 미존재 · 휴지통 상태 아니면 false.
func Restore(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	for i := range store {
		if store[i].ID == id {
			if store[i].DeletedAt == "" {
				return false
			}
			store[i].DeletedAt = ""
			persist()
			return true
		}
	}
	return false
}

// Purge — 영구삭제(하드, 이슈 #14). store 에서 제거 + 활성이면 해제.
// 관련 findings·scanruns cascade 는 호출부(webui)에서 처리한다.
func Purge(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	for i := range store {
		if store[i].ID == id {
			store = append(store[:i], store[i+1:]...)
			if activeID == id {
				activeID = ""
			}
			persist()
			return true
		}
	}
	return false
}

// Get — id 로 조회.
func Get(id string) (Project, bool) {
	mu.Lock()
	defer mu.Unlock()
	for _, p := range store {
		if p.ID == id {
			return p, true
		}
	}
	return Project{}, false
}

// Active — 활성 프로젝트.
func Active() (Project, bool) {
	mu.Lock()
	id := activeID
	mu.Unlock()
	if id == "" {
		return Project{}, false
	}
	return Get(id)
}

// SetActive — 활성 프로젝트 지정. 존재하고 휴지통이 아니어야 성공 (이슈 #14).
func SetActive(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	for _, p := range store {
		if p.ID == id && p.DeletedAt == "" {
			activeID = id
			persist()
			return true
		}
	}
	return false
}

// Update — 프로젝트 필드 수정. modified 갱신.
func Update(id string, mutate func(*Project)) bool {
	mu.Lock()
	defer mu.Unlock()
	for i := range store {
		if store[i].ID == id {
			mutate(&store[i])
			store[i].Modified = time.Now().Format("2006-01-02 15:04:05")
			persist()
			return true
		}
	}
	return false
}

// SetCredentials — 프로젝트 인증정보를 암호화해 저장 (§5.1 FR-1.4). 평문 미저장.
func SetCredentials(id string, c Credentials) error {
	pt, err := json.Marshal(c)
	if err != nil {
		return err
	}
	enc, err := secret.Encrypt(pt)
	if err != nil {
		return err
	}
	if !Update(id, func(p *Project) { p.EncCreds = enc }) {
		return fmt.Errorf("project 없음: %s", id)
	}
	return nil
}

// GetCredentials — 저장된 인증정보 복호화 (내부 주입용; API 노출 금지).
func GetCredentials(id string) (Credentials, bool) {
	p, ok := Get(id)
	if !ok || p.EncCreds == "" {
		return Credentials{}, false
	}
	pt, err := secret.Decrypt(p.EncCreds)
	if err != nil {
		return Credentials{}, false
	}
	var c Credentials
	if json.Unmarshal(pt, &c) != nil {
		return Credentials{}, false
	}
	return c, true
}

// CredentialSummary — 인증정보 요약(마스킹, 키 이름만). API 노출 안전.
func CredentialSummary(id string) CredSummary {
	c, ok := GetCredentials(id)
	if !ok {
		return CredSummary{HasCreds: false}
	}
	s := CredSummary{HasCreds: true}
	for k := range c.Cookies {
		s.Cookies = append(s.Cookies, k)
	}
	for k := range c.Headers {
		s.Headers = append(s.Headers, k)
	}
	for name, ic := range c.Identities {
		s.Identities = append(s.Identities, name)
		if ic.Admin {
			s.Admins = append(s.Admins, name)
		}
	}
	return s
}

// CredsToAuth — 프로젝트 인증정보를 복호화해 auth 주입용 형태로 변환 (없으면 ok=false).
// 활성-프로젝트 전역 주입(webui/mcpserver)과 테넌트 injector 구성이 공유한다 (§5.1 FR-2.5/FR-3.6).
func CredsToAuth(pid string) (auth.Config, []auth.Identity, bool) {
	c, ok := GetCredentials(pid)
	if !ok {
		return auth.Config{}, nil, false
	}
	cfg := auth.Config{Cookies: c.Cookies, Headers: c.Headers}
	var ids []auth.Identity
	for name, ic := range c.Identities {
		ids = append(ids, auth.Identity{Name: name, Cookies: ic.Cookies, Headers: ic.Headers, Privileged: ic.Admin})
	}
	return cfg, ids, true
}

// ── 프로젝트별 멤버 ACL (§5.1 FR-1.4) ──────────────────────────────

// IsMember — uid 가 프로젝트 멤버(또는 소유자)인가.
func IsMember(pid, uid string) bool {
	p, ok := Get(pid)
	if !ok {
		return false
	}
	if p.Owner == uid {
		return true
	}
	for _, m := range p.Members {
		if m == uid {
			return true
		}
	}
	return false
}

// AddMember — 멤버 추가(중복 무시).
func AddMember(pid, uid string) bool {
	return Update(pid, func(p *Project) {
		for _, m := range p.Members {
			if m == uid {
				return
			}
		}
		p.Members = append(p.Members, uid)
	})
}

// RemoveMember — 멤버 제거.
func RemoveMember(pid, uid string) bool {
	return Update(pid, func(p *Project) {
		out := p.Members[:0]
		for _, m := range p.Members {
			if m != uid {
				out = append(out, m)
			}
		}
		p.Members = out
	})
}

// Count — 프로젝트 수.
func Count() int {
	mu.Lock()
	defer mu.Unlock()
	return len(store)
}

// Reset — 테스트용 초기화.
func Reset() {
	mu.Lock()
	store, activeID, seq = nil, "", 0
	mu.Unlock()
}
