// Package webui — 읽기전용 웹 GUI (§5.1 중앙 웹). JSON API + 임베드된 React 정적파일.
//
// 프론트 소스는 frontend/ (별도 루트, React+Vite+TS). 빌드 산출물이 dist/ 로 떨어지고
// go:embed 로 단일 바이너리에 포함된다 → 폐쇄망 단일 exe 배포.
// API 는 라이브 상태를 그대로 노출한다(읽기전용). 제어는 MCP 계층이 담당.
package webui

import (
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"proxypoc/internal/advisor"
	"proxypoc/internal/audit"
	"proxypoc/internal/auth"
	"proxypoc/internal/bundle"
	"proxypoc/internal/ca"
	"proxypoc/internal/checklist"
	"proxypoc/internal/coverage"
	"proxypoc/internal/crawler"
	"proxypoc/internal/detector"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/finding"
	"proxypoc/internal/llm"
	"proxypoc/internal/payload"
	"proxypoc/internal/project"
	"proxypoc/internal/proxyengine"
	"proxypoc/internal/recon/discover"
	"proxypoc/internal/report"
	"proxypoc/internal/retention"
	"proxypoc/internal/reverify"
	"proxypoc/internal/rules"
	"proxypoc/internal/scanengine"
	"proxypoc/internal/scope"
	"proxypoc/internal/session"
	"proxypoc/internal/tenant"
	"proxypoc/internal/traffic"
	"proxypoc/internal/user"
)

//go:embed all:dist
var distFS embed.FS

// authDisabled — 개발용 no-auth 모드(§5.1). true 면 세션 검사를 건너뛰고 항상 리더로 동작.
var authDisabled bool

// SetAuthDisabled — 기동 시 config 로 설정.
func SetAuthDisabled(v bool) { authDisabled = v }

// SetArtifactExt — 산출물 네이티브 확장자 설정(bundle 위임, FR-1.6).
func SetArtifactExt(ext string) { bundle.SetExt(ext) }

// retentionDays — 휴지통 자동 영구삭제 보존기간(일). 프론트 D-n 표시에 노출 (이슈 #15).
var retentionDays = 30

// SetRetentionDays — 기동 시 config 로 설정.
func SetRetentionDays(n int) {
	if n > 0 {
		retentionDays = n
	}
}

// 요청별 사용자 (§5.1 FR-1.1 멀티유저). 전역 current 를 덮어쓰지 않고 요청 context 로 신원을 전달한다.
type ctxKey int

const userKey ctxKey = 0

// reqUser — 이 요청의 인증 사용자 (context). 없으면 빈 사용자.
func reqUser(r *http.Request) user.User {
	if u, ok := r.Context().Value(userKey).(user.User); ok {
		return u
	}
	return user.User{}
}

// canAccess — 프로젝트별 ACL (§5.1 FR-1.4). 리더는 전체 접근(admin), 수행원은 소유/멤버만.
func canAccess(u user.User, pid string) bool {
	if u.Role == user.RoleLeader {
		return true
	}
	return project.IsMember(pid, u.ID)
}

// requireAccess — 접근 불가면 403 후 false.
func requireAccess(w http.ResponseWriter, r *http.Request, pid string) bool {
	if !canAccess(reqUser(r), pid) {
		http.Error(w, "접근 권한 없음(프로젝트 멤버 아님): "+pid, http.StatusForbidden)
		return false
	}
	return true
}

// Serve — 웹 GUI 서버 시작(블로킹). 보통 goroutine 으로 띄운다.
func Serve(addr string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/stats", jsonHandler(stats))
	mux.HandleFunc("/api/findings", jsonHandler(func() any { return finding.ByProject(activePID()) }))
	mux.HandleFunc("/api/scanruns", jsonHandler(func() any { return scanengine.RunsByProject(activePID()) }))
	mux.HandleFunc("/api/coverage", jsonHandler(func() any { return coverage.Report() }))
	mux.HandleFunc("/api/endpoints", endpointsListHandler)                                             // 필터·검색·페이징 (이슈 #7, 무필터=하위호환)
	mux.HandleFunc("GET /api/endpoints/tree", jsonHandler(func() any { return endpoints.Snapshot() })) // 풍부한 트리 (이슈 #7)
	mux.HandleFunc("GET /api/endpoints/detail", endpointDetailHandler)                                 // 단일 엔드포인트 상세 (이슈 #7)
	mux.HandleFunc("GET /api/proxy", jsonHandler(proxyStatus))                                         // 공용 프록시 상태 (이슈 #5)
	mux.HandleFunc("POST /api/proxy/capture", proxyCaptureHandler)                                     // 캡처 on/off (proxy:control, 리더)
	mux.HandleFunc("/api/crawl", crawlHandler)                                                         // GET: 크롤 실행목록 / POST: 크롤 시작(Explore)
	mux.HandleFunc("/api/crawl-modes", jsonHandler(func() any {
		return map[string]any{"headless_available": crawler.HeadlessAvailable()}
	}))
	mux.HandleFunc("/api/scan", scanHandler)                                // POST: 스캔 시작(캡처된 공격면 대상, §5.3)
	mux.HandleFunc("POST /api/scanruns/{id}/pause", scanControl("pause"))   // FR-3.8 일시정지
	mux.HandleFunc("POST /api/scanruns/{id}/resume", scanControl("resume")) // FR-3.8 재개
	mux.HandleFunc("POST /api/scanruns/{id}/cancel", scanControl("cancel")) // FR-3.8 취소
	mux.HandleFunc("/api/traffic", jsonHandler(func() any { return traffic.Recent(50) }))
	mux.HandleFunc("/api/rules", jsonHandler(func() any { return rules.Snapshot() }))
	mux.HandleFunc("/api/detectors", jsonHandler(func() any { return detector.Catalog() }))
	mux.HandleFunc("/api/payloads", jsonHandler(func() any { return payload.Info() }))
	mux.HandleFunc("/api/llm-decisions", jsonHandler(func() any { return llm.Decisions() }))
	mux.HandleFunc("/api/rule-candidates", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, advisor.CandidatesLang(langOf(r))) }) // X-Lang 반영(#18)
	mux.HandleFunc("/api/rules/adopt", ruleAdoptHandler)                                                                                     // POST: 추천 후보를 활성 룰로 채택(rule:promote)
	mux.HandleFunc("/api/checkitems", jsonHandler(func() any { return checklist.Current().CheckItems }))
	mux.HandleFunc("/api/vulndefs", jsonHandler(func() any { return checklist.Current().Vulns })) // 취약점 카탈로그(name_en 포함, 화면 로케일용 #18)
	mux.HandleFunc("/api/projects", projectsHandler)                                              // GET list / POST create (§5.1)
	mux.HandleFunc("/api/activate-project", activateHandler)                                      // POST {id} (§5.1)
	mux.HandleFunc("/api/project-credentials", credentialsHandler)                                // GET summary / POST set (encrypted, §5.1 FR-1.4)
	mux.HandleFunc("/api/active-project", jsonHandler(func() any {
		p, _ := project.Active()
		return p
	}))
	// RESTful 프로젝트 리소스 (§5.1 FR-1.1) — 멤버 ACL(FR-1.4)로 접근 통제.
	mux.HandleFunc("GET /api/projects/{id}/findings", func(w http.ResponseWriter, r *http.Request) {
		if !requireAccess(w, r, r.PathValue("id")) {
			return
		}
		writeJSON(w, finding.ByProject(r.PathValue("id")))
	})
	mux.HandleFunc("GET /api/projects/{id}/scanruns", func(w http.ResponseWriter, r *http.Request) {
		if !requireAccess(w, r, r.PathValue("id")) {
			return
		}
		writeJSON(w, scanengine.RunsByProject(r.PathValue("id")))
	})
	mux.HandleFunc("GET /api/projects/{id}/coverage", func(w http.ResponseWriter, r *http.Request) {
		if !requireAccess(w, r, r.PathValue("id")) {
			return
		}
		writeJSON(w, coverage.ReportFor(r.PathValue("id")))
	})
	mux.HandleFunc("GET /api/projects/{id}/report", func(w http.ResponseWriter, r *http.Request) {
		if !requireAccess(w, r, r.PathValue("id")) {
			return
		}
		writeJSON(w, map[string]any{"headers": report.Headers, "rows": report.RowsFor(r.PathValue("id"))})
	})
	mux.HandleFunc("GET /api/projects/{id}/credentials", func(w http.ResponseWriter, r *http.Request) {
		if !requireAccess(w, r, r.PathValue("id")) {
			return
		}
		writeJSON(w, project.CredentialSummary(r.PathValue("id")))
	})
	// 멤버 관리 (FR-1.4 ACL, 리더 전용)
	mux.HandleFunc("POST /api/projects/{id}/members", memberAddHandler)
	mux.HandleFunc("POST /api/projects/{id}/members/remove", memberRemoveHandler)
	// 프로젝트 소프트 삭제 · 휴지통 (이슈 #14, 리더 전용·감사)
	mux.HandleFunc("GET /api/projects/trash", jsonHandler(func() any { return project.Trash() }))
	mux.HandleFunc("POST /api/projects/{id}/delete", projectDeleteHandler)   // 소프트 삭제
	mux.HandleFunc("POST /api/projects/{id}/restore", projectRestoreHandler) // 복구
	mux.HandleFunc("POST /api/projects/{id}/purge", projectPurgeHandler)     // 영구삭제(cascade)
	// 프록시 멀티테넌시 (§5.1 FR-1.1) — 프로젝트별 전용 프록시 포트
	mux.HandleFunc("/api/tenants", jsonHandler(func() any { return tenant.List() }))
	mux.HandleFunc("POST /api/tenants/{id}/start", tenantStartHandler)
	mux.HandleFunc("POST /api/tenants/{id}/stop", tenantStopHandler)
	mux.HandleFunc("GET /api/tenants/{id}/endpoints", func(w http.ResponseWriter, r *http.Request) {
		if !requireAccess(w, r, r.PathValue("id")) {
			return
		}
		eps, _ := tenant.Endpoints(r.PathValue("id"))
		writeJSON(w, eps)
	})
	mux.HandleFunc("GET /api/tenants/{id}/traffic", func(w http.ResponseWriter, r *http.Request) {
		if !requireAccess(w, r, r.PathValue("id")) {
			return
		}
		tr, _ := tenant.Traffic(r.PathValue("id"), 50)
		writeJSON(w, tr)
	})
	// finding 검토 상태 전이(FR-4.4) + 낙관적 동시성(FR-1.3)
	mux.HandleFunc("POST /api/findings/{id}/status", findingStatusHandler)
	mux.HandleFunc("POST /api/findings/clear", clearFindingsHandler)
	// 네이티브 번들 export/import (FR-1.6 DRM 비간섭)
	mux.HandleFunc("GET /api/projects/{id}/bundle", bundleDownload)
	mux.HandleFunc("/api/import-bundle", importBundleHandler) // POST (leader)
	mux.HandleFunc("/api/artifact-ext", jsonHandler(func() any { return map[string]any{"ext": bundle.Ext()} }))
	// 권한/역할·감사 (§5.1 FR-1.4/1.5)
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		u := reqUser(r) // 요청별 신원 (멀티유저)
		writeJSON(w, map[string]any{"user": u, "can": user.Actions(u.Role), "auth_disabled": authDisabled})
	})
	mux.HandleFunc("/api/users", usersHandler)                           // GET: 목록 / POST: 생성(user:manage, 리더 전용)
	mux.HandleFunc("POST /api/users/{id}/delete", userDeleteHandler)     // 계정 삭제(user:manage)
	mux.HandleFunc("POST /api/users/{id}/password", userPasswordHandler) // 비밀번호 재설정(user:manage)
	mux.HandleFunc("/api/audit", jsonHandler(func() any { return audit.List() }))
	mux.HandleFunc("/audit.csv", auditCSV)       // 감사 로그 CSV 내보내기 (규제 제출용 증적)
	mux.HandleFunc("/api/login", loginHandler)   // POST {username, password} (§5.1 FR-1.4)
	mux.HandleFunc("/api/logout", logoutHandler) // POST
	mux.HandleFunc("/api/reverify", reverifyHandler)
	mux.HandleFunc("/api/scan-diff", scanDiff)
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) { // X-Lang: 화면 취약점명·설명 로케일(#18)
		writeJSON(w, map[string]any{"headers": report.Headers, "rows": report.RowsLang(langOf(r))})
	})
	mux.HandleFunc("/api/evidence", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"headers": report.EvidenceHeaders, "rows": report.EvidenceRowsLang(langOf(r))})
	})
	mux.HandleFunc("/report.xlsx", reportDownload)
	mux.HandleFunc("/coverage.xlsx", coverageDownload)
	mux.HandleFunc("/api/auth", jsonHandler(authSummary))
	mux.HandleFunc("/api/login-seq", loginSeqHandler) // GET 마스킹 조회 / POST 설정(project:credentials, 리더)
	mux.HandleFunc("/api/schemes", jsonHandler(func() any {
		return map[string]any{"all": checklist.Schemes(), "selected": checklist.Selected()}
	}))

	mux.Handle("/", spaHandler())

	log.Printf("웹 GUI 시작: http://%s", addr)
	return http.ListenAndServe(addr, withAuth(mux))
}

// withAuth — /api/* (login 제외)는 유효 세션 필요(§5.1). 정적 앱은 항상 서빙(로그인 화면).
func withAuth(next http.Handler) http.Handler {
	open := map[string]bool{"/api/login": true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		var u user.User
		if strings.HasPrefix(p, "/api/") && !open[p] {
			if authDisabled {
				u, _ = user.Current() // 개발 모드: 기본 리더
			} else {
				uid := ""
				if c, err := r.Cookie(session.CookieName); err == nil {
					uid, _ = session.UserID(c.Value)
				}
				if uid == "" {
					http.Error(w, "인증 필요", http.StatusUnauthorized)
					return
				}
				u, _ = user.Get(uid) // 요청별 신원 (전역 덮어쓰기 없음 → 동시 사용자 격리)
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}

// loginHandler — POST {username, password}: 인증 → 세션 발급(쿠키) (§5.1 FR-1.4).
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	u, ok := user.Authenticate(in.Username, in.Password)
	if !ok {
		audit.Record(in.Username, "?", "user:login", in.Username, "denied", "인증 실패")
		http.Error(w, "인증 실패", http.StatusUnauthorized)
		return
	}
	// 멀티유저: 로그인은 세션만 발급(전역 current 미변경 → 동시 로그인 격리).
	tok := session.New(u.ID)
	http.SetCookie(w, &http.Cookie{
		Name: session.CookieName, Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(session.TTL.Seconds()),
	})
	audit.Record(u.Name, string(u.Role), "user:login", u.ID, "ok", "")
	writeJSON(w, u)
}

// logoutHandler — POST: 세션 무효화 (§5.1).
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(session.CookieName); err == nil {
		session.Delete(c.Value)
	}
	if u := reqUser(r); u.ID != "" {
		audit.Record(u.Name, string(u.Role), "user:logout", u.ID, "ok", "")
	}
	http.SetCookie(w, &http.Cookie{Name: session.CookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	writeJSON(w, map[string]any{"ok": true})
}

// Stats — 대시보드 요약.
type Stats struct {
	Endpoints     int      `json:"endpoints"`
	Hosts         int      `json:"hosts"`
	Findings      int      `json:"findings"`
	ScanRuns      int      `json:"scanruns"`
	Scope         []string `json:"scope"`
	Schemes       []string `json:"schemes"`
	SafeMode      bool     `json:"safe_mode"`
	CATrusted     bool     `json:"ca_trusted"`
	Rules         int      `json:"rules"`
	Detectors     int      `json:"detectors"`
	LLMProvider   string   `json:"llm_provider"`
	RiskProfile   string   `json:"risk_profile"`   // 최고 심각도 기반 (high/medium/low/none)
	RetentionDays int      `json:"retention_days"` // 휴지통 자동 영구삭제 보존기간(일) — D-n 표시용 (이슈 #15)
}

// authorize — 현재 사용자가 action 권한이 있는지. 없으면 403 + 감사기록 후 false.
func authorize(w http.ResponseWriter, r *http.Request, action, target string) (user.User, bool) {
	u := reqUser(r)
	if !user.Can(u.Role, action) {
		audit.Record(u.Name, string(u.Role), action, target, "denied", "권한 없음")
		http.Error(w, "권한 없음: "+action+" ("+string(u.Role)+")", http.StatusForbidden)
		return u, false
	}
	return u, true
}

// scanHandler — POST: 캡처된 공격면(endpoints.Targets)에 대해 스캔 시작 (scan:run 권한, §5.3).
func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST 필요", http.StatusMethodNotAllowed)
		return
	}
	u, ok := authorize(w, r, "scan:run", "scan")
	if !ok {
		return
	}
	var in struct {
		Detectors        []string `json:"detectors"`
		AllowDestructive bool     `json:"allow_destructive"`
		LLMReview        bool     `json:"llm_review"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	targets := endpoints.Targets()
	if len(targets) == 0 {
		http.Error(w, "공격면이 비어 있습니다 — 먼저 자동 크롤 또는 프록시 트래픽으로 엔드포인트를 캡처하세요", http.StatusBadRequest)
		return
	}
	sr := scanengine.Start(targets, detector.Select(in.Detectors),
		scanengine.Options{AllowDestructive: in.AllowDestructive, LLMReview: in.LLMReview})
	audit.Record(u.Name, string(u.Role), "scan:run", sr.ID, "ok", fmt.Sprintf("대상 %d · 탐지기 %d", sr.Targets, len(sr.Detectors)))
	log.Printf("[WEB ] %s(%s) scan %s (대상 %d)", u.Name, u.Role, sr.ID, sr.Targets)
	writeJSON(w, sr)
}

// ruleAdoptHandler — POST: LLM 추천 후보(signature)를 결정론적 룰로 채택 (rule:promote, 리더 전용).
// HITL 승인 단계 — 채택 즉시 활성 룰셋에 반영되고 rules.adopted.json 에 영속화된다.
func ruleAdoptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST 필요", http.StatusMethodNotAllowed)
		return
	}
	u, ok := authorize(w, r, "rule:promote", "rule")
	if !ok {
		return
	}
	var in struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Signature == "" {
		http.Error(w, "signature 필요", http.StatusBadRequest)
		return
	}
	var draft rules.Rule
	found := false
	for _, c := range advisor.Candidates() {
		if c.Signature == in.Signature {
			draft, found = c.DraftRule, true
			break
		}
	}
	if !found {
		http.Error(w, "해당 후보를 찾을 수 없습니다(로그가 변해 후보가 사라졌을 수 있음)", http.StatusNotFound)
		return
	}
	if !rules.Add(draft) {
		http.Error(w, "채택 실패 — 이미 채택된 룰이거나 패턴이 유효하지 않습니다", http.StatusConflict)
		return
	}
	audit.Record(u.Name, string(u.Role), "rule:promote", draft.Name, "ok", draft.Action+" "+draft.PathPattern)
	log.Printf("[WEB ] %s(%s) rule:promote %s (%s)", u.Name, u.Role, draft.Name, draft.Action)
	writeJSON(w, map[string]any{"adopted": draft})
}

// usersHandler — GET: 사용자 목록 / POST: 수행원·리더 계정 생성 (user:manage, 리더 전용, §5.1 FR-1.4).
// 비밀번호는 bcrypt 해시로만 저장되고 응답에 절대 노출되지 않는다(User.PasswordHash json:"-").
func usersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, user.List())
		return
	}
	u, ok := authorize(w, r, "user:manage", "user")
	if !ok {
		return
	}
	var in struct {
		Name     string `json:"name"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Password) < 6 {
		http.Error(w, "이름 필수 · 비밀번호 6자 이상", http.StatusBadRequest)
		return
	}
	role := user.Role(in.Role)
	if role != user.RoleLeader && role != user.RoleAnalyst {
		http.Error(w, "역할은 leader 또는 analyst 여야 합니다", http.StatusBadRequest)
		return
	}
	for _, ex := range user.List() { // 이름 중복 방지
		if ex.Name == in.Name {
			http.Error(w, "이미 존재하는 사용자 이름입니다: "+in.Name, http.StatusConflict)
			return
		}
	}
	nu := user.Create(in.Name, role, in.Password)
	audit.Record(u.Name, string(u.Role), "user:manage", nu.ID, "ok", "생성 "+nu.Name+"("+string(nu.Role)+")")
	log.Printf("[WEB ] %s(%s) user:create %s(%s)", u.Name, u.Role, nu.Name, nu.Role)
	writeJSON(w, nu) // PasswordHash 는 json:"-" 로 제외됨
}

// userDeleteHandler — 계정 삭제 (user:manage, 리더 전용). 자기 자신·마지막 리더는 삭제 불가(잠김 방지).
func userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	u, ok := authorize(w, r, "user:manage", "user")
	if !ok {
		return
	}
	id := r.PathValue("id")
	if id == u.ID {
		http.Error(w, "자기 자신은 삭제할 수 없습니다", http.StatusBadRequest)
		return
	}
	target, exists := user.Get(id)
	if !exists {
		http.Error(w, "해당 사용자가 없습니다", http.StatusNotFound)
		return
	}
	if target.Role == user.RoleLeader && user.Count(user.RoleLeader) <= 1 {
		http.Error(w, "마지막 리더는 삭제할 수 없습니다", http.StatusConflict)
		return
	}
	if !user.Delete(id) {
		http.Error(w, "삭제 실패", http.StatusConflict)
		return
	}
	audit.Record(u.Name, string(u.Role), "user:manage", id, "ok", "삭제 "+target.Name)
	log.Printf("[WEB ] %s(%s) user:delete %s(%s)", u.Name, u.Role, target.Name, id)
	writeJSON(w, map[string]any{"deleted": id})
}

// userPasswordHandler — 비밀번호 재설정 (user:manage, 리더 전용). 새 비밀번호는 6자 이상.
func userPasswordHandler(w http.ResponseWriter, r *http.Request) {
	u, ok := authorize(w, r, "user:manage", "user")
	if !ok {
		return
	}
	id := r.PathValue("id")
	target, exists := user.Get(id)
	if !exists {
		http.Error(w, "해당 사용자가 없습니다", http.StatusNotFound)
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if len(in.Password) < 6 {
		http.Error(w, "비밀번호는 6자 이상이어야 합니다", http.StatusBadRequest)
		return
	}
	if !user.SetPassword(id, in.Password) {
		http.Error(w, "재설정 실패", http.StatusInternalServerError)
		return
	}
	audit.Record(u.Name, string(u.Role), "user:manage", id, "ok", "비밀번호 재설정 "+target.Name)
	log.Printf("[WEB ] %s(%s) user:password %s(%s)", u.Name, u.Role, target.Name, id)
	writeJSON(w, map[string]any{"ok": true})
}

// loginSeqHandler — GET: 로그인 시퀀스 마스킹 조회 / POST: 설정 (project:credentials, 리더 전용, FR-2.5 세션 지속성).
// 비밀번호 등 필드 값은 응답에 노출하지 않는다(키만). POST는 로컬 신뢰 채널로 평문 수신(인메모리 주입기에만 반영).
func loginSeqHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, auth.LoginSnapshot())
		return
	}
	u, ok := authorize(w, r, "project:credentials", "login-seq")
	if !ok {
		return
	}
	var in auth.LoginSeq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "잘못된 요청", http.StatusBadRequest)
		return
	}
	auth.SetLogin(in)
	audit.Record(u.Name, string(u.Role), "project:credentials", "login-seq", "ok",
		fmt.Sprintf("로그인 시퀀스 설정(url=%s, 활성=%v)", in.URL, auth.LoginSnapshot().Enabled))
	log.Printf("[WEB ] %s(%s) login-seq 설정 (활성=%v)", u.Name, u.Role, auth.LoginSnapshot().Enabled)
	writeJSON(w, auth.LoginSnapshot())
}

// scanControl — 실행 중 스캔의 일시정지/재개/취소 (FR-3.8, scan:run 권한). op: pause|resume|cancel.
func scanControl(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := authorize(w, r, "scan:run", "scan")
		if !ok {
			return
		}
		id := r.PathValue("id")
		var done bool
		switch op {
		case "pause":
			done = scanengine.Pause(id)
		case "resume":
			done = scanengine.Resume(id)
		case "cancel":
			done = scanengine.Cancel(id)
		}
		if !done {
			http.Error(w, "해당 상태에서 불가한 요청입니다(이미 완료·중단되었거나 상태 불일치)", http.StatusConflict)
			return
		}
		audit.Record(u.Name, string(u.Role), "scan:"+op, id, "ok", "")
		log.Printf("[WEB ] %s(%s) scan:%s %s", u.Name, u.Role, op, id)
		sr, _ := scanengine.Status(id)
		writeJSON(w, sr)
	}
}

// reverifyHandler — GET: 이행점검 실행 목록 / POST: 취약 finding 재점검 실행 (scan:run 권한, FR-5.2/5.3).
func reverifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		u, ok := authorize(w, r, "scan:run", "reverify")
		if !ok {
			return
		}
		pid := ""
		if p, ok := project.Active(); ok {
			pid = p.ID
		}
		var items []finding.Finding
		for _, f := range finding.ByProject(pid) {
			if f.Status == "오탐" {
				continue // 오탐 확정 항목은 재점검 제외
			}
			items = append(items, f)
		}
		if len(items) == 0 {
			http.Error(w, "재점검할 취약 finding 이 없습니다(오탐 제외)", http.StatusBadRequest)
			return
		}
		run := reverify.Reverify(r.Context(), items, "manual")
		audit.Record(u.Name, string(u.Role), "reverify", run.ID, "ok",
			fmt.Sprintf("대상 %d · 조치 %d · 미조치 %d", run.Total, run.Fixed, run.Open))
		log.Printf("[WEB ] %s(%s) reverify %s (대상 %d)", u.Name, u.Role, run.ID, run.Total)
		writeJSON(w, run)
		return
	}
	writeJSON(w, reverify.Runs())
}

// crawlHandler — GET: 크롤 실행 목록 / POST: 자동 크롤(Explore) 시작 (scan:run 권한).
func crawlHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		u, ok := authorize(w, r, "scan:run", "crawl")
		if !ok {
			return
		}
		var in struct {
			Seed     string `json:"seed"`
			MaxPages int    `json:"max_pages"`
			MaxDepth int    `json:"max_depth"`
			Mode     string `json:"mode"`
			Discover bool   `json:"discover"` // 능동 콘텐츠 발견 옵트인 (#27)
			Budget   int    `json:"budget"`   // 능동 발견 요청 예산 (0 = 기본값)
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Seed == "" {
			http.Error(w, "seed URL 필요", http.StatusBadRequest)
			return
		}
		if in.Mode == "headless" && !crawler.HeadlessAvailable() {
			http.Error(w, "헤드리스 크롤 불가 — 이 서버에 Chrome/Chromium이 설치돼 있지 않습니다", http.StatusBadRequest)
			return
		}
		res := crawler.Start(in.Seed, crawler.Options{
			MaxPages: in.MaxPages, MaxDepth: in.MaxDepth, Mode: in.Mode,
			Discover: in.Discover, Budget: in.Budget,
		})
		audit.Record(u.Name, string(u.Role), "crawl", in.Seed, "ok", res.ID)
		// 능동 탐색은 파괴성·소음·법적 경계가 있다. 누가 언제 켰는지 별도로 남긴다 (#27).
		if in.Discover {
			budget := in.Budget
			if budget <= 0 {
				budget = discover.DefaultBudget
			}
			audit.Record(u.Name, string(u.Role), "crawl:discover", in.Seed, "ok",
				fmt.Sprintf("%s wordlist=%d budget=%d", res.ID, len(discover.Words()), budget))
			log.Printf("[WEB ] %s(%s) crawl:discover %s budget=%d → %s", u.Name, u.Role, in.Seed, budget, res.ID)
		}
		log.Printf("[WEB ] %s(%s) crawl %s → %s", u.Name, u.Role, in.Seed, res.ID)
		writeJSON(w, res)
		return
	}
	writeJSON(w, crawler.Runs())
}

// clearFindingsHandler — 도출 항목 전체 초기화 (파괴적, 리더 전용, 감사 기록).
// 영속화된 findings 가 재스캔으로 누적될 때 사용자가 명시적으로 리셋.
func clearFindingsHandler(w http.ResponseWriter, r *http.Request) {
	u, ok := authorize(w, r, "finding:clear", "all")
	if !ok {
		return
	}
	n := finding.Clear()
	audit.Record(u.Name, string(u.Role), "finding:clear", "all", "ok", itoa(n)+"건 삭제")
	log.Printf("[WEB ] %s(%s) clear_findings (%d건)", u.Name, u.Role, n)
	writeJSON(w, map[string]int{"cleared": n})
}

// bundleDownload — 프로젝트 네이티브 번들 다운로드 (FR-1.6). 사용자 지정 확장자로 저장돼 DRM 미간섭.
func bundleDownload(w http.ResponseWriter, r *http.Request) {
	data, base, err := bundle.Export(r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+base+bundle.Ext()+`"`)
	_, _ = w.Write(data)
}

// importBundleHandler — POST 네이티브 번들 파일 → 새 프로젝트+findings 복원 (FR-1.6, 리더).
func importBundleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	u, ok := authorize(w, r, "project:create", "import")
	if !ok {
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20)) // 16MB 상한
	if err != nil {
		http.Error(w, "읽기 실패", http.StatusBadRequest)
		return
	}
	np, n, err := bundle.Import(data)
	if err != nil {
		http.Error(w, "가져오기 실패: "+err.Error(), http.StatusBadRequest)
		return
	}
	audit.Record(u.Name, string(u.Role), "project:import", np.ID, "ok", np.Name)
	writeJSON(w, map[string]any{"project": np, "findings": n})
}

// findingStatusHandler — POST {status, version}: 검토 상태 전이(FR-4.4) + 낙관적 락(FR-1.3).
// 다른 사용자가 먼저 수정했으면 409 Conflict + 현재 finding 반환(재조회용).
func findingStatusHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, ok := authorize(w, r, "finding:confirm", id)
	if !ok {
		return
	}
	var in struct {
		Status  string `json:"status"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	f, err := finding.SetStatus(id, in.Status, in.Version, u.Name)
	switch err {
	case finding.ErrConflict:
		audit.Record(u.Name, string(u.Role), "finding:status", id, "conflict", "v"+itoa(in.Version)+"≠v"+itoa(f.Version))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusConflict) // 409
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "conflict", "current": f})
	case finding.ErrBadTransition:
		http.Error(w, "허용되지 않은 전이: "+f.Status+"→"+in.Status, http.StatusBadRequest)
	case finding.ErrNotFound:
		http.Error(w, "not found: "+id, http.StatusNotFound)
	case nil:
		audit.Record(u.Name, string(u.Role), "finding:status", id, "ok", f.Status)
		writeJSON(w, f)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// projectsHandler — GET: 프로젝트 목록 / POST: 생성 (§5.1). 생성은 리더 권한(FR-1.4).
func projectsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in struct {
			Name    string   `json:"name"`
			MainURL string   `json:"main_url"`
			Scope   []string `json:"scope"`
			Schemes []string `json:"schemes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Name == "" {
			http.Error(w, "name 필요", http.StatusBadRequest)
			return
		}
		u, ok := authorize(w, r, "project:create", in.Name)
		if !ok {
			return
		}
		mainURL := in.MainURL
		if mainURL == "" && len(in.Scope) > 0 {
			mainURL = "https://" + in.Scope[0]
		}
		p := project.Create(project.Project{Owner: u.ID, Name: in.Name, MainURL: mainURL, Scope: in.Scope, Schemes: in.Schemes})
		audit.Record(u.Name, string(u.Role), "project:create", p.ID, "ok", p.Name)
		log.Printf("[WEB ] %s(%s) create_project %s (%s)", u.Name, u.Role, p.ID, p.Name)
		writeJSON(w, p)
		return
	}
	// GET: 멤버 ACL 로 필터 (리더는 전체, 수행원은 접근 가능한 것만) — FR-1.4.
	u := reqUser(r)
	out := make([]project.Project, 0)
	for _, p := range project.List() {
		if canAccess(u, p.ID) {
			out = append(out, p)
		}
	}
	writeJSON(w, out)
}

// tenantStartHandler / tenantStopHandler — 프로젝트별 프록시 인스턴스 제어 (§5.1 FR-1.1).
func tenantStartHandler(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("id")
	u, ok := authorize(w, r, "project:activate", pid)
	if !ok {
		return
	}
	if !canAccess(u, pid) {
		http.Error(w, "접근 권한 없음(프로젝트 멤버 아님)", http.StatusForbidden)
		return
	}
	info, err := tenant.Start(pid)
	if err != nil {
		http.Error(w, "시작 실패: "+err.Error(), http.StatusBadRequest)
		return
	}
	audit.Record(u.Name, string(u.Role), "tenant:start", pid, "ok", "")
	writeJSON(w, info)
}

func tenantStopHandler(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("id")
	u, ok := authorize(w, r, "project:activate", pid)
	if !ok {
		return
	}
	tenant.Stop(pid)
	audit.Record(u.Name, string(u.Role), "tenant:stop", pid, "ok", "")
	writeJSON(w, map[string]any{"ok": true})
}

// endpointsListHandler — 캡처된 엔드포인트 목록 (이슈 #7). 쿼리 필터·검색·페이징 지원.
// 필터: host(부분일치)·method(정확)·verdict(부분일치)·auth(true/false)·q(host+path 검색).
// 페이징: limit/offset (전체 개수는 X-Total-Count 헤더). 무필터·무페이징이면 기존과 동일한 전체 배열 반환(하위호환).
func endpointsListHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := strings.ToLower(q.Get("host"))
	method := strings.ToUpper(q.Get("method"))
	verdict := strings.ToLower(q.Get("verdict"))
	qs := strings.ToLower(q.Get("q"))
	authFilter := q.Get("auth")                                // "" | "true" | "false"
	sourceFilter := strings.ToLower(q.Get("source"))           // "" | "spec" | "discover" | ... (부분일치)
	includeUnverified := q.Get("include_unverified") == "true" // 라이브니스 미통과 노출 (#28)
	authOnly := q.Get("auth_only") == "true"                   // 인증 뒤에만 보이는 표면만 (#38)

	// 기본은 verified 만(#26 의 Targets 가 unverified 를 기본 제외). 토글 시 전체 조회로 전환.
	targets := endpoints.Targets()
	if includeUnverified {
		targets = endpoints.TargetsAll()
	}
	sort.Slice(targets, func(i, j int) bool { // 안정적 순서(페이징·표시)
		if targets[i].Host != targets[j].Host {
			return targets[i].Host < targets[j].Host
		}
		return targets[i].Path < targets[j].Path
	})

	out := make([]endpoints.Target, 0, len(targets))
	for _, t := range targets {
		if host != "" && !strings.Contains(strings.ToLower(t.Host), host) {
			continue
		}
		if method != "" && !containsFold(t.Methods, method) {
			continue
		}
		if verdict != "" && !strings.Contains(strings.ToLower(t.Verdict), verdict) {
			continue
		}
		if qs != "" && !strings.Contains(strings.ToLower(t.Host+t.Path), qs) {
			continue
		}
		if authFilter == "true" && !t.Auth {
			continue
		}
		if authFilter == "false" && t.Auth {
			continue
		}
		if sourceFilter != "" && !strings.Contains(strings.ToLower(t.Source), sourceFilter) {
			continue
		}
		if authOnly && !t.AuthOnly {
			continue
		}
		out = append(out, t)
	}

	total := len(out)
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	end := total
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	out = out[offset:end]

	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	writeJSON(w, out)
}

// endpointDetailHandler — 단일 엔드포인트 상세 (이슈 #7). ?host=&path= (concrete path 도 정규화해서 조회).
func endpointDetailHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	path := r.URL.Query().Get("path")
	if host == "" || path == "" {
		http.Error(w, "host·path 쿼리 필요", http.StatusBadRequest)
		return
	}
	n, ok := endpoints.Find(host, endpoints.NormalizePath(path))
	if !ok {
		http.Error(w, "해당 엔드포인트를 찾을 수 없습니다", http.StatusNotFound)
		return
	}
	n.Children = nil // 단일 노드 상세 (자식 제외)
	writeJSON(w, n)
}

// containsFold — 대소문자 무시 문자열 슬라이스 포함 검사.
func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// proxyStatus — 공용 프록시(:8080) 상태 (이슈 #5). 리슨 주소·캡처 여부·스코프 호스트 수·누적 캡처 수·공격면 규모.
func proxyStatus() any {
	sm := endpoints.Summary()
	return map[string]any{
		"listen":            proxyengine.ListenAddr(),
		"capturing":         proxyengine.CaptureEnabled(),
		"scope_hosts":       len(scope.HostsSnapshot()),
		"captured_requests": proxyengine.CapturedCount(),
		"endpoints":         sm.Endpoints,
		"hosts":             sm.Hosts,
	}
}

// proxyCaptureHandler — POST {on}: 공용 프록시 엔드포인트 캡처 on/off (proxy:control, 리더 전용, 감사 기록).
// 프록시 프로세스·스코프·인증·판단 파이프라인은 영향 없이 공격면 기록만 멈추거나 재개한다.
func proxyCaptureHandler(w http.ResponseWriter, r *http.Request) {
	u, ok := authorize(w, r, "proxy:control", "proxy")
	if !ok {
		return
	}
	var in struct {
		On bool `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	proxyengine.SetCapture(in.On)
	state := "off"
	if in.On {
		state = "on"
	}
	audit.Record(u.Name, string(u.Role), "proxy:control", "capture", "ok", "capture="+state)
	log.Printf("[WEB ] %s(%s) proxy:capture %s", u.Name, u.Role, state)
	writeJSON(w, proxyStatus())
}

// memberAddHandler / memberRemoveHandler — 프로젝트 멤버 관리 (FR-1.4 ACL, 리더 전용).
func memberAddHandler(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("id")
	u, ok := authorize(w, r, "project:members", pid)
	if !ok {
		return
	}
	var in struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.UserID == "" {
		http.Error(w, "user_id 필요", http.StatusBadRequest)
		return
	}
	if !project.AddMember(pid, in.UserID) {
		http.Error(w, "not found: "+pid, http.StatusNotFound)
		return
	}
	audit.Record(u.Name, string(u.Role), "project:member_add", pid, "ok", in.UserID)
	p, _ := project.Get(pid)
	writeJSON(w, p)
}

func memberRemoveHandler(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("id")
	u, ok := authorize(w, r, "project:members", pid)
	if !ok {
		return
	}
	var in struct {
		UserID string `json:"user_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	project.RemoveMember(pid, in.UserID)
	audit.Record(u.Name, string(u.Role), "project:member_remove", pid, "ok", in.UserID)
	p, _ := project.Get(pid)
	writeJSON(w, p)
}

// projectDeleteHandler — POST: 프로젝트 소프트 삭제(휴지통 이동, 이슈 #14). 리더 전용·감사.
// 활성 프로젝트는 삭제 불가 → 먼저 다른 프로젝트로 전환해야 한다(스코프 꼬임 방지).
func projectDeleteHandler(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("id")
	u, ok := authorize(w, r, "project:delete", pid)
	if !ok {
		return
	}
	if ap, ok := project.Active(); ok && ap.ID == pid {
		http.Error(w, "활성 프로젝트는 삭제할 수 없습니다 — 먼저 다른 프로젝트로 전환하세요", http.StatusConflict)
		return
	}
	if !project.Delete(pid) {
		http.Error(w, "삭제 실패(없거나 이미 휴지통에 있음)", http.StatusConflict)
		return
	}
	audit.Record(u.Name, string(u.Role), "project:delete", pid, "ok", "소프트 삭제(휴지통)")
	log.Printf("[WEB ] %s(%s) project:delete %s (soft)", u.Name, u.Role, pid)
	writeJSON(w, map[string]any{"deleted": pid})
}

// projectRestoreHandler — POST: 휴지통에서 복구(이슈 #14). 리더 전용·감사.
func projectRestoreHandler(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("id")
	u, ok := authorize(w, r, "project:delete", pid)
	if !ok {
		return
	}
	if !project.Restore(pid) {
		http.Error(w, "복구 실패(없거나 휴지통에 있지 않음)", http.StatusConflict)
		return
	}
	audit.Record(u.Name, string(u.Role), "project:restore", pid, "ok", "휴지통에서 복구")
	log.Printf("[WEB ] %s(%s) project:restore %s", u.Name, u.Role, pid)
	writeJSON(w, map[string]any{"restored": pid})
}

// projectPurgeHandler — POST: 영구삭제(이슈 #14). 리더 전용·감사.
// 휴지통에 있는 프로젝트만 대상 · findings·scanruns 를 함께 cascade 삭제(고아 데이터 방지).
func projectPurgeHandler(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("id")
	u, ok := authorize(w, r, "project:delete", pid)
	if !ok {
		return
	}
	p, exists := project.Get(pid)
	if !exists {
		http.Error(w, "not found: "+pid, http.StatusNotFound)
		return
	}
	if p.DeletedAt == "" {
		http.Error(w, "휴지통에 있는 프로젝트만 영구삭제할 수 있습니다(먼저 삭제하세요)", http.StatusConflict)
		return
	}
	nf, ns := retention.PurgeCascade(pid) // findings·scanruns cascade + project.Purge (이슈 #14/#15 공용)
	detail := fmt.Sprintf("영구삭제 (findings %d · scanruns %d)", nf, ns)
	audit.Record(u.Name, string(u.Role), "project:purge", pid, "ok", detail)
	log.Printf("[WEB ] %s(%s) project:purge %s (%s)", u.Name, u.Role, pid, detail)
	writeJSON(w, map[string]any{"purged": pid, "findings": nf, "scanruns": ns})
}

// activateHandler — POST {id}: 활성 프로젝트 전환 + 엔진에 scope·스킴 적용 (§5.1).
func activateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	u, ok := authorize(w, r, "project:activate", in.ID)
	if !ok {
		return
	}
	if !canAccess(u, in.ID) { // 멤버 ACL (FR-1.4)
		audit.Record(u.Name, string(u.Role), "project:activate", in.ID, "denied", "멤버 아님")
		http.Error(w, "접근 권한 없음(프로젝트 멤버 아님)", http.StatusForbidden)
		return
	}
	if !project.SetActive(in.ID) {
		http.Error(w, "not found: "+in.ID, http.StatusNotFound)
		return
	}
	p, _ := project.Get(in.ID)
	scope.Configure(p.Scope, p.AllowPaths, p.ExcludePaths)
	schemes := make([]checklist.Scheme, 0, len(p.Schemes))
	for _, s := range p.Schemes {
		schemes = append(schemes, checklist.Scheme(s))
	}
	checklist.SetSelected(schemes)
	applyCredentials(p.ID) // 암호화 인증정보 복호화·주입 (§5.1 FR-1.4)
	audit.Record(u.Name, string(u.Role), "project:activate", p.ID, "ok", p.Name)
	log.Printf("[WEB ] %s(%s) activate_project %s (%s)", u.Name, u.Role, p.ID, p.Name)
	writeJSON(w, p)
}

// applyCredentials — 프로젝트 인증정보 복호화 후 auth 엔진 주입 (§5.1 FR-1.4 / FR-2.5 / FR-3.6).
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

// credentialsHandler — GET: 인증정보 요약(마스킹) / POST: 인증정보 암호화 저장 (§5.1 FR-1.4, 리더 전용).
func credentialsHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "id 필요", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost {
		u, ok := authorize(w, r, "project:credentials", id)
		if !ok {
			return
		}
		var c project.Credentials
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if err := project.SetCredentials(id, c); err != nil {
			http.Error(w, "저장 실패: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// 활성 프로젝트면 즉시 재주입.
		if ap, ok := project.Active(); ok && ap.ID == id {
			applyCredentials(id)
		}
		audit.Record(u.Name, string(u.Role), "project:credentials", id, "ok", "encrypted")
		writeJSON(w, project.CredentialSummary(id))
		return
	}
	// GET: 마스킹 요약(값 절대 노출 안 함)
	writeJSON(w, project.CredentialSummary(id))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// langOf — 요청 로케일. 프론트가 보내는 X-Lang 헤더 기준, en 만 인식하고 기본은 ko (#18).
func langOf(r *http.Request) string {
	if r.Header.Get("X-Lang") == "en" {
		return "en"
	}
	return "ko"
}

// activePID — 활성 프로젝트 id (없으면 "" = 전체).
func activePID() string {
	if p, ok := project.Active(); ok {
		return p.ID
	}
	return ""
}

func stats() any {
	trusted, _ := ca.IsTrusted()
	schemes := make([]string, 0)
	for _, s := range checklist.Selected() {
		schemes = append(schemes, string(s))
	}
	pid := activePID()
	return Stats{
		Endpoints:     len(endpoints.Targets()),
		Hosts:         len(scope.HostsSnapshot()),
		Findings:      len(finding.ByProject(pid)),
		ScanRuns:      len(scanengine.RunsByProject(pid)),
		Scope:         scope.HostsSnapshot(),
		Schemes:       schemes,
		SafeMode:      scanengine.SafeMode(),
		CATrusted:     trusted,
		Rules:         len(rules.Snapshot()),
		Detectors:     len(detector.Catalog()),
		LLMProvider:   llm.ProviderName(),
		RiskProfile:   riskProfile(),
		RetentionDays: retentionDays,
	}
}

// reportDownload — 도출리스트 xlsx 다운로드 (§5.4, FR-4.1). 온디맨드 export.
func reportDownload(w http.ResponseWriter, r *http.Request) {
	// ?lang=en 이면 영문 리포트, 그 외(기본)는 한국어 (#18).
	lang := "ko"
	fname := "report.xlsx"
	if r.URL.Query().Get("lang") == "en" {
		lang, fname = "en", "findings.xlsx"
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	if _, err := report.WriteExcelToLang(w, lang); err != nil {
		http.Error(w, "excel 생성 실패: "+err.Error(), http.StatusInternalServerError)
	}
}

// scanDiff — 두 ScanRun 간 공격면 diff (§5.5, FR-5.4). ?from=SR-1&to=SR-2
func scanDiff(w http.ResponseWriter, r *http.Request) {
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(reverify.DiffRuns(from, to))
}

// auditCSV — 감사 로그 CSV 내보내기 (FR-1.5 증적). UTF-8 BOM 으로 Excel 한글 깨짐 방지.
func auditCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit.csv"`)
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"시각", "사용자", "역할", "행위", "대상", "결과", "상세"})
	for _, e := range audit.List() {
		_ = cw.Write([]string{e.Time, e.User, e.Role, e.Action, e.Target, e.Result, e.Detail})
	}
	cw.Flush()
}

// coverageDownload — 점검결과표 xlsx 다운로드 (§5.4, FR-4.3). 스킴별 시트 + 요약.
func coverageDownload(w http.ResponseWriter, r *http.Request) {
	// ?lang=en 이면 영문 점검결과표, 그 외(기본)는 한국어 (#18).
	lang := "ko"
	fname := "coverage.xlsx"
	if r.URL.Query().Get("lang") == "en" {
		lang, fname = "en", "coverage_en.xlsx"
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	if _, err := report.WriteCoverageExcelToLang(w, lang); err != nil {
		http.Error(w, "excel 생성 실패: "+err.Error(), http.StatusInternalServerError)
	}
}

// authSummary — 인증주입(FR-2.5)·다중신원(FR-3.6) 요약. 값은 마스킹, 키 이름만 노출(§8).
func authSummary() any {
	snap := auth.Snapshot()
	type ident struct {
		Name       string   `json:"name"`
		Cookies    []string `json:"cookies"`
		Headers    []string `json:"headers"`
		Privileged bool     `json:"privileged,omitempty"` // 고권한(관리자) 신원 — 수직 권한상승 대조 기준
	}
	ids := make([]ident, 0)
	for _, id := range auth.Identities() {
		row := ident{Name: id.Name, Cookies: make([]string, 0), Headers: make([]string, 0), Privileged: id.Privileged}
		for k := range id.Cookies {
			row.Cookies = append(row.Cookies, k)
		}
		for k := range id.Headers {
			row.Headers = append(row.Headers, k)
		}
		ids = append(ids, row)
	}
	return map[string]any{
		"enabled":    auth.Enabled(),
		"cookies":    snap["cookies"],
		"headers":    snap["headers"],
		"identities": ids,
	}
}

// riskProfile — 현재 finding 중 최고 심각도.
func riskProfile() string {
	rank := map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4}
	best, name := 0, "none"
	for _, f := range finding.ByProject(activePID()) {
		if r := rank[f.Severity]; r > best {
			best, name = r, f.Severity
		}
	}
	return name
}

func jsonHandler(fn func() any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(fn())
	}
}

// spaHandler — 임베드된 정적파일 서빙. 파일이 없으면 index.html 로 폴백(SPA 라우팅).
func spaHandler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		log.Fatalf("webui embed 오류: %v", err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fs.Stat(sub, trimLeadingSlash(r.URL.Path)); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/" // 없는 경로 → index.html (클라이언트 라우팅)
		}
		fileServer.ServeHTTP(w, r)
	})
}

func trimLeadingSlash(p string) string {
	if p == "/" || p == "" {
		return "index.html"
	}
	if p[0] == '/' {
		return p[1:]
	}
	return p
}
