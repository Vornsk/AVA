# CODEBASE — 현재 상태 조사

> 조사 기준 커밋: `c3ea722` (`1차 파일 업데이트`) · 조사일 2026-08-10 · **읽기 전용 감사, 소스 미변경**
>
> 표기 규칙: 사실은 `파일:줄` 근거를 붙였고, 근거로 확정할 수 없는 판단은 **추정**으로 표시했다.
> 이 문서는 "무엇이 있어야 하는가"(→ `docs/spec.md`)가 아니라 **"지금 무엇이 실제로 있는가"**만 기술한다.

---

## 0. 한 줄 요약 — 이 레포는 현재 빌드되지 않는다

두 개의 독립적인 단절이 있다.

1. **백엔드 컴파일 실패.** `backend/internal/webui/webui.go:46`의 `//go:embed all:dist`가 가리키는 `backend/internal/webui/dist/`가 없다.
   ```
   $ cd backend && go build ./...
   internal/webui/webui.go:46:12: pattern all:dist: no matching files found
   ```
   이 하나의 에러가 `internal/webui`와, 이를 import하는(`backend/cmd/proxy/main.go:35`) **제품 본체 `cmd/proxy`**를 함께 무너뜨린다.

2. **프론트엔드 소스 부재.** `frontend/index.html:10`이 로드하는 `/src/main.tsx`가 존재하지 않는다. `frontend/src/`에는 `api.ts` 하나뿐이고, 레포 전체에 `.tsx`/`.jsx`/`.css`/`vite.config.*`/`tsconfig.json`이 **0개**다.

두 단절은 서로 맞물려 있다. `dist/`는 프론트 빌드 산출물인데, 그 프론트를 빌드할 소스가 없다.
**따라서 현재 커밋에서는 어떤 경로로도 제품을 빌드·실행할 수 없다.**

반면 그 아래 백엔드 로직은 대부분 진짜다: 11,256줄의 비테스트 Go 코드, 테스트를 가진 21개 패키지 전부 통과, 스텁·`panic`·빈 함수 0개.
**"완성된 백엔드가 프론트엔드와 빌드 산출물을 잃은 상태"**로 읽힌다.

| 검증 항목 | 결과 |
|---|---|
| `go build ./...` | ❌ 실패 (embed 1건) |
| `go vet ./...` | ❌ 동일 원인 실패 |
| `go test ./...` | ⚠️ 21개 패키지 통과, 2개 `[setup failed]` (동일 embed 원인). **실패한 테스트 단언은 0건** |
| `npm run build` | ❌ 엔트리 `main.tsx` 미존재로 실패 (**추정** — `npm install` 미실행, 정적 분석 기반) |

> **갱신 (이 문서 작성 이후 — 두 단절 모두 해소됨):**
>
> 프론트엔드 소스 19개 파일(2,755줄 — 화면 11개 + Login·App·main.tsx·공용 컴포넌트)과
> `vite.config.ts`·`tsconfig.json`이 도입되어, **위 1·2번이 모두 사라졌다.**
> `vite.config.ts`의 `build.outDir`이 `../backend/internal/webui/dist`를 가리키므로
> `npm run build` 산출물이 그대로 임베드 대상이 된다.
>
> fresh clone 기준 실측: `npm ci` ✅ → `npm run build` ✅ (1,811 모듈) →
> `npx tsc --noEmit` **에러 0건**(`strict` 활성) → `go build`·`go vet`·`go test` 모두 종료코드 0.
> `internal/webui`와 `cmd/proxy`가 정상 컴파일된다.
>
> 빌드 순서 의존이 생겼다: **`npm run build`를 `go build`보다 먼저** 수행해야 한다
> (`dist/`는 빌드 산출물이라 커밋하지 않는다). README "빠른 실행" 절 참조.
>
> **이 문서의 나머지 부분은 UI 도입 이전 상태를 기술한다.** 특히 §3.4·§4.1·§5의
> "UI 부재" 관련 서술은 더 이상 유효하지 않다 — `api.ts`는 12개 파일이 import하는
> 실사용 코드가 되었고(`usePoll` 51회, `apiPost` 22회), 화면 11개가 모두 존재한다.
> 그 외 백엔드 분석(§1~§3.3, §3.5~§3.8, §4.2~§4.4, §5.2~§5.6, §6, §7)은 그대로 유효하다.
>
> **갱신 2 (이슈 #5 · 저장소 정비 — 이 문서 작성 이후):**
>
> - **`.gitignore` 추가됨**(레포 루트 — `ca.key`·`secret.key`·`users.json`·`projects.json`·빌드 산출물 차단)
>   → §1의 "`.gitignore`가 레포 전체에 없다"와 §7 이슈 표의 관련 항목은 **무효**.
> - **`.github/` 이슈·PR 템플릿 추가**(이슈 폼 3종 + PR 템플릿 + config). CI 워크플로는 아직 없음.
> - **이슈 #5 (공용 프록시 캡처 제어):** 공용 :8080 프록시의 엔드포인트 캡처를 런타임에 on/off·상태 조회.
>   - `webui` 라우트 **58 → 60** (`GET /api/proxy`, `POST /api/proxy/capture`), LOC 1,017 → 1,057
>   - `mcpserver` 툴 **54 → 56** (`proxy_status`, `set_capture` — `proxy:control` 리더·감사), LOC 797 → 831
>   - `proxyengine` +`control.go`(캡처 on/off·상태), LOC 153 → 196
>   - 이 삽입으로 §4.2·§4.3의 **개별 라인 참조가 소폭 밀렸다**(`webui.go` +약 41줄, `mcpserver.go` +약 34줄). 개수·설명은 패키지 표·§4.2·§4.3에 반영함.

---

## 1. 디렉터리 구조와 각 최상위 폴더의 역할

```
AVA/
├── README.md                 제품 소개·빌드·실행 안내 (5.4KB)
├── backend/                  Go 단일 바이너리 (실질적으로 제품 전체)
│   ├── go.mod, go.sum
│   ├── local.config.example.yaml
│   ├── cmd/                  4개 실행 바이너리
│   └── internal/             34개 도메인 패키지
├── frontend/                 React SPA — **껍데기 (파일 4개)**
└── docs/                     한글 설계 문서 + 문서 사이트 생성기 + 고아 YAML
```

~~`.gitignore`가 **레포 전체에 없다.**~~ **(해소 — 갱신 2 참조)** 레포 루트에 `.gitignore`가 추가되어 `README.md`가 커밋 금지로 지정한 `ca.key`·`secret.key`·`users.json`·`projects.json` 및 빌드 산출물이 차단된다. (해당 파일들이 커밋되어 있지 않음은 `git ls-files`로 확인.)

### 1.1 `backend/cmd/` — 실행 바이너리 4개

| 바이너리 | LOC | 역할 | 완성도 |
|---|---|---|---|
| `cmd/proxy` | 229 | **제품 본체.** 설정 로드 → CA 확보 → 상태 복원 → MCP 서버(goroutine) + Web UI(goroutine) + MITM 프록시(메인) 3개 리스너를 한 프로세스에서 구동 | 완성형이나 **현재 빌드 불가** |
| `cmd/vulnapp` | 337 | 탐지기 자체 검증용 **의도적 취약 웹앱**. 21개 엔드포인트가 취약/안전 쌍으로 구성 | 완성 (테스트 픽스처로서) |
| `cmd/mcpclient` | 89 | 자체 MCP 서버를 호출하는 데모 클라이언트. 하드코딩된 ~15개 호출 스크립트 | **데모** (`main.go:1` "B-1 데모 클라이언트" 자기 표기) |
| `cmd/mitmclient` | 52 | 외부 mitmproxy MCP 애드온 호출 데모 | **폐기 예정 스켈레톤** (`main.go:1` "B-2 데모 (throwaway)"). 짝이 되는 `mitm_mcp_addon.py`가 레포에 없어 실행 불가 |

### 1.2 `backend/internal/` — 34개 패키지

LOC는 테스트 포함 기준. **test 0**은 `_test.go`가 없는 패키지.

| 패키지 | 역할 | LOC | test |
|---|---|---|---|
| `detector` | **엔진 핵심.** 26종 취약점 탐지기 (XSS/SQLi/traversal 등) | 2,972 | 1,172 |
| `webui` | HTTP JSON API 60개 라우트 + SPA 임베드 서빙 | 1,057 | **0** |
| `endpoints` | 공격면 트리 (host → 정규화 경로 → 파라미터) + JSON 영속 | 870 | 230 |
| `crawler` | 정적 + 헤드리스(chromedp) 크롤러 | 860 | 171 |
| `mcpserver` | MCP 툴 56종 (StreamableHTTP) | 831 | **0** |
| `checklist` | 규제 점검항목표 3계층, YAML 로드 | 765 | 219 |
| `llm` | 프로바이더 추상화 (mock/ollama/anthropic/openai) | 661 | 123 |
| `scanengine` | 스캔 실행 오케스트레이션, 일시정지/재개/취소, safe-mode | 601 | 251 |
| `report` | xlsx 내보내기 (excelize): 도출리스트 + 커버리지 시트 | 596 | 113 |
| `payload` | 페이로드/워드리스트 + 민감정보 패턴 | 544 | 87 |
| `project` | 프로젝트 엔티티, 멤버 ACL, 암호화 인증정보 | 466 | 160 |
| `auth` | 인증 주입(쿠키/헤더), 다중 신원, 재로그인 | 423 | 88 |
| `finding` | 도출항목 저장소 + 검토 상태머신 + 낙관적 락 | 361 | 99 |
| `user` | 사용자/역할 (bcrypt), RBAC 권한 맵 | 324 | 59 |
| `rules` | 결정론적 전송 전 룰 스테이지 + 채택 룰 영속 | 274 | 74 |
| `scope` | 호스트/경로 허용목록 강제 (하드 가드레일) | 255 | 61 |
| `ca` | 자체서명 CA 생성 + OS 신뢰저장소 설치/검증 | 252 | **0** |
| `reverify` | 이행점검 실행 + 스캔 간 diff | 250 | 83 |
| `advisor` | 반복 LLM 판정 → 룰 초안 승격 (HITL) | 193 | 57 |
| `bundle` | 네이티브 프로젝트 내보내기/가져오기 (`.cgpkg`) | 169 | 77 |
| `tenant` | 프로젝트별 격리 프록시 인스턴스 (멀티테넌시) | 163 | **0** |
| `proxyengine` | goproxy 조립: scope → rule → LLM → 캡처 훅 + 캡처 on/off·상태 제어(control.go) | 196 | 83 |
| `secret` | AES-256-GCM 마스터 키 + 암복호 | 152 | 55 |
| `vulnlab` | detector 테스트 전용 인프로세스 취약 핸들러 | 145 | **0** |
| `config` | YAML 로컬/프로젝트 설정 load-or-create | 116 | **0** |
| `traffic` | 최근 요청 링버퍼 (200개) | 115 | 45 |
| `profile` | 저장된 스캔 프로파일 → `profiles.json` | 84 | 23 |
| `masking` | 로그/URL 민감값 마스킹 | 76 | 33 |
| `session` | 인메모리 로그인 세션 토큰 | 62 | **0** |
| `audit` | 감사 로그 (append + 파일 저장, 500개 상한) | 59 | **0** |
| `coverage` | checklist × detector × finding 조인 (import 순환 회피용) | 54 | **0** |

**테스트 공백의 핵심:** 테스트가 없는 가장 큰 두 패키지가 정확히 **외부 공격면 전체**인 `webui`(1,017줄)와 `mcpserver`(797줄)다. 합계 1,814줄, 전체 코드의 약 12.5%. 보안상 민감한 `ca`(CA 생성 + OS 신뢰저장소 변경)와 `session`(토큰 발급)도 테스트가 없다.

### 1.3 `docs/`

| 파일 | 내용 |
|---|---|
| `spec.md` (394줄) | **원본 요구사항·아키텍처 정의서 v0.7.** FR-1.x~FR-7.x 번호 체계, 데이터 모델, 설정 3계층, 점검항목 3층 스키마, LLM 게이트웨이, 변경이력 |
| `00-아키텍처.md` (282줄) | 설계 배경, goproxy 선택 근거, 판단 파이프라인, 탐지기 25종, 멀티테넌시, 빌드·실행, 겪은 함정, 로드맵 |
| `01`~`11-*.md` | 화면별 명세 11개 (개요/프로젝트/정찰/스캔/취약점/커버리지/리포트/이행점검/룰제안/감사/사용자). 각 문서 상단에 사이드바 위치·소스 경로·권한, 하단에 "뒷단 연결" 엔드포인트 표 |
| `build.mjs` (413줄) | 의존성 0의 자체 구현 마크다운 → HTML 변환기. `node docs/build.mjs`로 `docs/index.html` 생성 |
| `index.html` (666줄) | `build.mjs` **생성물**. 오프라인 열람 가능한 자기완결 문서 SPA. 직접 편집 금지 (`README.md:34`) |
| `vulndefs.yaml`, `checkitems.{kii,fin,mobile}.yaml` | **고아 산출물** — §5.4 참조 |

> 아이러니: 이 레포에서 실제로 동작하는 유일한 프론트엔드 산출물은 `docs/index.html`(문서 사이트)이고, 제품 UI인 `frontend/index.html`은 빈 껍데기다.

### 1.4 `frontend/` — 파일 4개가 전부

```
frontend/index.html          12줄
frontend/package.json        25줄
frontend/package-lock.json   2,550줄
frontend/src/api.ts          299줄
```
`git ls-files frontend`도 동일한 4개만 반환한다. `node_modules`는 설치되어 있지 않다.

---

## 2. 스택·라이브러리 — 실제 import 기준

### 2.1 백엔드 (Go)

**Go 1.26.5** (`backend/go.mod:3`). 패치 버전까지 고정한 이례적 지정.
모듈명은 `proxypoc` (`go.mod:1`) — 레포명 `AVA`와 불일치.

**직접 의존성 8개 — 전부 실제로 import되어 사용 중. 미사용 0개.**

| 모듈 | 버전 | 실제 import 위치 |
|---|---|---|
| `github.com/elazarl/goproxy` | v1.8.5 | `internal/proxyengine/proxy.go:10`, `internal/ca/ca.go:21` |
| `github.com/modelcontextprotocol/go-sdk` | v1.7.0 | `internal/mcpserver/mcpserver.go:16`, `cmd/mcpclient/main.go:13`, `cmd/mitmclient/main.go:12` |
| `github.com/xuri/excelize/v2` | v2.11.0 | `internal/report/report.go:12`, `internal/report/coverage.go:7` |
| `github.com/chromedp/chromedp` | v0.16.0 | `internal/crawler/headless.go:14` |
| `github.com/chromedp/cdproto` | (날짜 의사버전) | `internal/crawler/headless.go:13` |
| `golang.org/x/net` | v0.56.0 | `internal/crawler/crawler.go:22` (`/html`만) |
| `golang.org/x/crypto` | v0.53.0 | `internal/user/user.go:14` (`/bcrypt`만) |
| `gopkg.in/yaml.v3` | v3.0.1 | `internal/config/config.go:14`, `internal/checklist/checklist.go:19` |

`go.mod:16-34`의 indirect 20개는 전부 전이 의존성으로, 직접 import되지 않는 것이 정상이다.

**주목할 점 — `go.sum`에는 있으나 어디에서도 import되지 않는 것들:**
`stretchr/testify`, `google/go-cmp`, `golang-jwt/jwt/v5`, `coder/websocket` 등. 특히 **testify가 go.sum에 있지만 단 한 번도 import되지 않았다** — 이것이 "표준 `testing`만 사용" 방침을 뒷받침한다.

**DB 드라이버가 전혀 없다.** `database/sql`, `lib/pq`, `go-sqlite3`, GORM/ent/sqlx 모두 부재. 영속화는 전부 JSON 파일이다(§5).

### 2.2 프론트엔드 (TypeScript)

`frontend/package.json`은 **Vite 6 + React 18 + Tailwind 4 + lucide-react**를 선언한다 (`package.json:12-23`).

**그러나 실제 소스 import는 단 한 줄이다** — `frontend/src/api.ts:2`:
```ts
import { useEffect, useRef, useState } from 'react'
```

| 구분 | 목록 |
|---|---|
| 선언됐으나 **미사용** | `react-dom`, `lucide-react`, `tailwindcss`, `@tailwindcss/vite`, `@vitejs/plugin-react`, `@types/react-dom`, `typescript` |
| 실제 사용 | `react`, `@types/react` **뿐** |
| 사용되나 미선언 | 없음 |

`tsconfig.json`이 없으므로 **TypeScript는 현재 설정상 타입체크되지 않는다.** 또한 `package.json:7-9`의 어떤 스크립트도 `tsc`를 호출하지 않는다(`"build": "vite build"`만 존재) — 표준 Vite+React 템플릿의 `"build": "tsc -b && vite build"`와 대비된다. 즉 타입 오류가 빌드를 막지 못하는 구조다.

---

## 3. 이미 확립된 패턴

### 3.1 HTTP 핸들러 — 표준 `net/http.ServeMux`만 사용

chi/gin/gorilla 없음. Go 1.22+ 패턴 문법을 쓰며, 두 등록 형식이 같은 mux에 공존한다 (`internal/webui/webui.go:90`):

- **경로만 등록** (메서드는 핸들러 내부에서 검사): `mux.HandleFunc("/api/scan", scanHandler)` — `webui.go:101`
- **메서드+와일드카드**: `mux.HandleFunc("POST /api/scanruns/{id}/pause", scanControl("pause"))` — `webui.go:102`. 값은 `r.PathValue("id")`로 읽는다 (`webui.go:501`)

**대표 핸들러 형태** (`webui.go:307-333`) — 메서드 가드 → `authorize()` → 익명 구조체로 JSON 디코드 → 도메인 호출 → `audit.Record` → `log.Printf` → `writeJSON`:

```go
func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST 필요", http.StatusMethodNotAllowed); return }
	u, ok := authorize(w, r, "scan:run", "scan")
	if !ok { return }
	var in struct { Detectors []string `json:"detectors"`; ... }
	_ = json.NewDecoder(r.Body).Decode(&in)
	...
	audit.Record(u.Name, string(u.Role), "scan:run", sr.ID, "ok", ...)
	writeJSON(w, sr)
}
```

읽기 전용 엔드포인트용 보일러플레이트 축약 헬퍼: `jsonHandler(fn func() any)` (`webui.go:983`), `writeJSON(w, v)` (`webui.go:862`, 항상 `Cache-Control: no-store` + 2칸 들여쓰기).

MCP 쪽은 완전히 다른 패턴이다: `mcp.AddTool(server, &mcp.Tool{Name, Description}, func(ctx, req, args T) (*mcp.CallToolResult, any, error))` — `mcpserver.go:146` 이하, `jsonResult`/`textResult` 헬퍼(`mcpserver.go:791`/`787`).

### 3.2 상태 관리 / 저장소 — DB 없음, 패키지 전역 + JSON 스냅샷

세 가지 형태가 공존하며, **구세대 → 신세대 마이그레이션이 진행 중**이다.

1. **구세대 (전역 변수 + 전역 뮤텍스)** — `internal/finding` (`finding.go:52-56`):
   ```go
   var (mu sync.Mutex; store []Finding; seq int)
   ```
   `Add()`는 lock → append → 스냅샷 복사 → **unlock 후** `persist(snapshot)` (`finding.go:78-82`). 이 규율은 `finding.go:77`에 주석으로 문서화되어 있다.

2. **같은 구세대지만 규약이 반대** — `internal/user`의 `persist()`는 **호출자가 이미 lock을 쥐고 있을 것을 요구**한다 (`user.go:114`). API 응답용 `User.PasswordHash`는 `json:"-"`이라 디스크용 별도 타입 `storedUser`(`user.go:81-87`)를 둔다.
   > **추정**: finding(락 밖 저장) vs user(락 안 저장)의 불일치는 의도된 설계가 아니라 패키지 간 실제 편차로 보인다.

3. **신세대 (인스턴스 + 인스턴스 뮤텍스)** — `internal/traffic`(`traffic.go:20-23`), `internal/endpoints`(`endpoints.go:67-71`). 노출된 인스턴스 타입(`Log`, `Tree`)에 자체 `mu`를 두고, 패키지 전역 `def` 인스턴스 + 얇은 위임 함수를 함께 제공한다(`traffic.go:60-70`). `endpoints.Tree`의 `name` 필드는 `""`면 인메모리 전용(테넌트용), 비어있지 않으면 해당 파일로 덤프한다(`endpoints.go:68`, `:549`) — 멀티테넌시 이행 경로다.

**락 사용 현황:**

| 형태 | 패키지 |
|---|---|
| 전역 `sync.Mutex` | `finding`(:53), `user`(:74), `project`(:63), `audit`(:25), `session`(:24), `tenant`(:46) |
| 전역 `sync.RWMutex` | `scope`(:23), `payload`(:22), `rules`(:40), `secret`(:16), `detector/tools`(:25), `auth`(:28 + 재로그인 single-flight용 `loginMu`:35) |
| **구조체 필드 뮤텍스** | `traffic`(:21), `endpoints`(:69), `crawler`(:51), `scanengine`(:74) |
| 기타 | `detector` 레이트리미터 `sync.Mutex`(:34) + `atomic.AddUint64` nonce(:365), `crawler/headless` `sync.Once`(:21) |

> **추정**: 멀티테넌시 지원을 위해 "전역 싱글턴 + 전역 뮤텍스" → "인스턴스 + 인스턴스 뮤텍스"로 이행 중이며, `traffic.go:1-5`가 이를 "Phase 2"로 명시한다. `finding`·`user`·`project`·`audit`·`session`은 **아직 미이행**이라, 테넌트 프록시들이 하나의 finding 저장소를 공유한다.

### 3.3 의존성 주입 — **없음. 전역 세터 기반.**

컴포지션 루트가 없다. `backend/cmd/proxy/main.go:38-177`이 그 역할에 가장 가까우며, 140줄에 걸친 전역 상태 변경 시퀀스다:

```
scope.Configure(...)          :59    → scope/scope.go:141 var def
rules.Load / LoadAdopted      :60-62 → rules/rules.go:39
auth.Set / SetIdentities      :63-65 → auth/auth.go:113 var def
detector.SetToolPaths         :66
payload.SetXSS                :67
scanengine.SetSafeMode        :69
checklist.LoadOrCreate        :75
secret.Init / user.Load       :100,107
finding.Load / endpoints.Load :135-136
llm.SetProvider(llm.New(...)) :149    ← 유일한 진짜 주입점이지만 이것도 전역 세터
webui.SetAuthDisabled         :166
```

**유일한 생성자 주입 지점**은 테넌트/프록시 경로다: `proxyengine.NewFor(stages, sc *scope.Enforcer, tr *endpoints.Tree, inj *auth.Injector, tl *traffic.Log, tag string)` (`proxyengine/proxy.go:28`). `proxyengine.New`(:23)는 이를 전역 기본값에 바인딩한 래퍼일 뿐이고, `tenant.Start`는 테넌트별 인스턴스로 `NewFor`를 호출한다(`tenant/tenant.go:29-32`). 코드베이스에서 DI 형태를 갖춘 유일한 곳이며, 그마저 "Phase 2 미완"으로 명시되어 있다(`tenant/tenant.go:5` — traffic/auth는 아직 테넌트 분리 안 됨).

**결과:** `webui`와 `mcpserver`가 **동일한 전역 엔진 상태를 조율 없이 각자 변경**한다. `webui.go:805-811`과 `mcpserver.go:768-776`(`applyProject`)은 정확히 같은 일을 하는 중복 로직이다.

### 3.4 API 호출 방식 (프론트) — 범용 트랜스포트 3개가 전부

`frontend/src/api.ts`는 **26개 인터페이스 + 3개 함수**로 구성된다.

| 함수 | 위치 | 시그니처 |
|---|---|---|
| `apiGet<T>` | `api.ts:261` | `(path: string) => Promise<T>` |
| `apiPost<T>` | `api.ts:264` | `(path: string, body: unknown) => Promise<T>` |
| `usePoll<T>` | `api.ts:275` | `(path, ms = 4000) => {data, error, loading}` React 훅 |

- **메커니즘:** 네이티브 `fetch` (`api.ts:255`, `:265`). axios 없음.
- **Base URL 처리 없음.** `fetch(path, ...)`에 호출자 문자열을 그대로 넘긴다(`api.ts:255`). 환경변수나 prefix 상수가 전무하므로 항상 same-origin 상대 경로 전제다. 백엔드 임베드 서빙 구조와는 맞지만, `npm run dev`(:5173)에서는 Vite proxy 설정이 필요한데 `vite.config`가 없어 성립하지 않는다 — `docs/00-아키텍처.md:187`이 기술한 "`/api`를 백엔드로 프록시"가 실제로 없다.
- **인증 처리 명시적으로 없음.** Authorization 헤더도, 토큰 저장소도, `credentials: 'include'`도 없다. 백엔드가 쿠키 세션 방식(`webui.go:225-229`)이라 same-origin 기본 동작으로 우연히 성립하는 구조다. **401 처리 로직이 없어** 세션 만료 시 로그인 화면 리다이렉트 같은 처리가 부재하다.
- **경로 상수·도메인 래퍼가 하나도 없다.** `getStats()`, `startScan()` 같은 함수가 없어 백엔드 라우트 표면과 대조할 클라이언트 목록 자체가 존재하지 않는다.

### 3.5 에러 처리

**백엔드:**
- **센티넬 에러**는 두 패키지에만 있다: `finding`(`ErrConflict`, `ErrBadTransition`, `ErrNotFound` — `finding.go:114-116`), `bundle`(`ErrNotFound`, `ErrBadFormat` — `bundle.go:28-29`). 소비 측은 `errors.Is`가 아니라 `switch err { case finding.ErrConflict: ... }`를 쓴다(`webui.go:650-665`).
- **`%w` 래핑은 희귀하다** — `ca/ca.go:33`과 `ca/certmgr.go:112` 두 곳뿐. 나머지는 `%v` 또는 평이한 `errors.New`.
- **HTTP 에러 응답은 거의 전부 평문**이다: `http.Error(w, "<한글 메시지>", <status>)`. 구조화된 JSON 에러 바디는 **`webui.go:653-655`의 409 충돌 응답 단 하나**뿐이다(`{"error":"conflict","current":<finding>}`). → **프론트가 에러를 일관되게 파싱할 수 없는 API 불일치**다.
- 에러 메시지는 한글 사용자 문장이다: `"공격면이 비어 있습니다 — 먼저 자동 크롤 또는 프록시 트래픽으로 엔드포인트를 캡처하세요"` (`webui.go:325`).
- 의도적 에러 무시가 광범위하다: `_ = json.NewDecoder(r.Body).Decode(&in)` (`webui.go:322`, `:390`, `:457`, `:771`), 모든 persist 함수의 `_ = os.WriteFile(...)`.

**프론트:** 단일 규약. `res.ok` 실패 시 `throw new Error(\`${path} → ${res.status}\`)` (`api.ts:256`, `:270`). 상태코드 분기 없음, 응답 본문의 에러 메시지는 버려진다. 위의 409 낙관적 락을 구분할 구조가 아니다. `usePoll`은 throw 대신 `setError(String(e))`로 흡수한다(`api.ts:288`).

### 3.6 네이밍

- **파일:** 소문자, 언더스코어 없음, 개념 단위 명명(`scanengine.go`, `certmgr.go`, `headless.go`, `seed.go`). 다중 파일 패키지는 레이어가 아니라 관심사로 분할.
- **패키지:** 소문자 단어 하나, 도메인 개념당 하나. 전부 `internal/` 아래 — 모듈 외부로 노출되는 것이 없다.
- **타입:** Go 관용 PascalCase(`Finding`, `ScanRun`, `Enforcer`, `Injector`, `Tree`, `Log`). 미노출 탐지기 구조체는 소문자(`securityHeaders{}`, `blindSQLi{}` — `detector.go:76-102`).
- **생성자:** `New()` → `*T`가 표준(`auth.New()` `auth.go:40`, `traffic.New()` `traffic.go:25`, `scope.New(...)` `scope.go:30`, `endpoints.NewTree()` `endpoints.go:75`). 변형은 `NewFor`(`proxyengine/proxy.go:28`) 또는 `New<Provider>`(`llm.NewOllama`, `NewAnthropic`, `NewOpenAI`).
- **인터페이스가 전 백엔드에 3개뿐**이고, 셋 다 **소비하는 패키지에 선언**되어 있다(올바른 Go 스타일):
  - `llm.Provider` — `llm/llm.go:65`
  - `detector.Detector` — `detector/detector.go:67`
  - `detector.ToolBased` — `detector/tools.go:56` (선택적 능력, `detector.go:121`에서 타입 단언으로 검사)
- **주석:** 모든 패키지·노출 심볼에 `// Name — 설명 (§스펙참조, FR-x.y)` 형식의 한글 doc 주석이 붙어 있다. 스펙 요구사항 추적성(`FR-1.4`, `§5.1`)이 코드 전반에 박혀 있으며, **일관성이 매우 높은 강한 컨벤션**이다.

**프론트 타이핑 스타일:** 전부 `interface` 선언(type alias/enum/zod 없음). optional은 `?:`, nullable은 `string[] | null` union(`api.ts:51`, `:89`, `:239-240`). **상태값이 string literal union이 아니라 그냥 `string` + 주석**이다 — `api.ts:44` `reverify_status?: string // 조치완료 | 미조치 | 부분조치 | 신규발생`, `api.ts:109` `action: string // block | allow`, `api.ts:190` `role: string // leader | analyst`. 즉 타입 안전성이 주석 수준에 머문다. 응답은 `res.json() as Promise<T>`(`api.ts:257`)로 런타임 검증 없이 단언한다.

### 3.7 테스트 스타일 — 표준 `testing`만, 대부분 테이블 주도가 **아님**

- **testify 0회 사용** (go.sum에는 존재하나 import 없음).
- 단언은 수동: `if got != want { t.Errorf(...) }` (예: `scanengine_test.go:99-106`).
- 테이블 주도는 **단 한 곳** — `detector/vulnlab_test.go:42`. 나머지는 순차 시나리오 테스트.
- 픽스처는 도메인 인터페이스를 구현하는 로컬 스텁 타입(`slowDetector`/`destructiveDet` — `scanengine_test.go:77-96`).
- 통합 테스트는 실제 서버를 띄운다: `httptest.NewTLSServer(vulnlab.Handler())` (`detector/vulnlab_test.go:17`, `:54`). `internal/detector` 테스트가 26.4초 걸리는 이유다.
- 프로덕션 코드에 테스트용 훅이 있다: `audit.Reset()`(`audit.go:53`, `// Reset — 테스트용`), `clock func() time.Time = time.Now` 주입(`audit.go:27`).
- **`t.Parallel()`이 어디에도 없다** — 패키지 전역 상태를 많이 쓰는 구조와 일관된다.

### 3.8 설정 로딩

2계층 YAML, 둘 다 load-or-create (`internal/config/config.go`):

- `LoadLocal("local.config.yaml")` → `Local` (`config.go:30-39`): `proxy_addr`, `mcp_addr`, `web_addr`, `llm{provider,model,endpoint,api_key}`, `tools`, `safe_mode`, `auth_disabled`, `artifact_ext`
- `LoadProject("project.config.yaml")` → `Project` (`config.go:43-55`): `scope`, `schemes`, `allow_paths`, `exclude_paths`, `recon_allow`, `stages`, `rules`, `auth`, `login`, `identities`, `payloads`
- `loadOrCreate` (`config.go:101-116`): 읽기 실패 → 기본값 marshal + 헤더 주석 → `os.WriteFile(path, ..., 0644)`. **unmarshal 실패 시에는 로그만 남기고 조용히 기본값을 유지한다**(`config.go:112`) — 잘못된 설정이 로그 외에는 드러나지 않는다.
- 기본값: `defaultLocal()` `config.go:63-72` (`:8080`, `127.0.0.1:8765`, `127.0.0.1:8090`, provider `mock`, ext `.cgpkg`), `defaultProject()` `config.go:74-84`
- **경로가 전부 CWD 상대다** (`cmd/proxy/main.go:46`, `:58`). §5.3 참조.

`local.config.example.yaml`(35줄)은 4개 LLM 프로바이더를 설명하는 템플릿이다. 다만 `openai`를 프로바이더로 문서화하고 `llm.New`도 실제 지원하는데(`llm/llm.go:29`), `config.LLM.Provider`의 doc 주석(`config.go:23`)에는 `mock | ollama | anthropic`만 적혀 있다 — 사소한 문서 드리프트.

---

## 4. 라우팅 / 화면 목록 — 동작 vs 껍데기

### 4.1 프론트 화면 — **도달 가능한 화면 0개**

라우터가 없다. `react-router` 계열이 `package.json`에 선언되지 않았고 라우팅 코드도 없다.
문서는 11개 화면을 소스 경로까지 지정해 상세히 기술하지만, **해당 파일이 하나도 존재하지 않는다.**

| # | 화면 | 문서가 지정한 소스 | 실제 |
|---|---|---|---|
| 01 | 개요 | `frontend/src/pages/Overview.tsx` (`docs/01-개요.md:3`) | 없음 |
| 02 | 프로젝트 | `frontend/src/pages/Projects.tsx` (`docs/02-프로젝트.md:3`) | 없음 |
| 03 | 정찰 | `frontend/src/pages/Recon.tsx` (`docs/03-정찰.md:3`) | 없음 |
| 04 | 스캔 | `frontend/src/pages/Scan.tsx` (`docs/04-스캔.md:3`) | 없음 |
| 05 | 취약점 | `frontend/src/pages/Findings.tsx` (`docs/05-취약점.md:3`) | 없음 |
| 06 | 커버리지 | `frontend/src/pages/Coverage.tsx` (`docs/06-커버리지.md:3`) | 없음 |
| 07 | 리포트 | `frontend/src/pages/Report.tsx` (`docs/07-리포트.md:3`) | 없음 |
| 08 | 이행점검 | `frontend/src/pages/Reverify.tsx` (`docs/08-이행점검.md:3`) | 없음 |
| 09 | 룰 제안 | `frontend/src/pages/Advisor.tsx` (`docs/09-룰제안.md:3`) | 없음 |
| 10 | 감사 | `frontend/src/pages/Audit.tsx` (`docs/10-감사.md:3`) | 없음 |
| 11 | 사용자 | `frontend/src/pages/Users.tsx` (`docs/11-사용자.md:3`) | 없음 |

로그인 화면도 마찬가지다. `README.md:74`의 데모 계정 `leader/leader123`을 입력할 폼이 없다.

**`frontend/src/api.ts` 299줄 전체가 데드코드다.** 이 파일을 import하는 파일이 레포에 없고, export된 3개 함수와 26개 인터페이스 전부 호출자·사용처가 0이다.

> **추정**: 26개 인터페이스가 백엔드 응답 모델을 충실히 반영하고 있는 점으로 보아, `api.ts`는 삭제되었거나 애초에 커밋되지 않은 UI의 잔존물로 보인다.

### 4.2 백엔드 라우트 — **60개 등록, 전부 실제 로직**

> 이슈 #5로 `GET /api/proxy`·`POST /api/proxy/capture` 2개가 추가됐다(58→60). 아래 표의
> 등록 줄·`@줄` 참조는 스냅샷 값이라 이 삽입(webui.go +약 41줄)만큼 소폭 밀려 있다 — §0 갱신 2 참조.

`internal/webui/webui.go`의 `Serve()`에 등록. 정확히 **59개 `mux.HandleFunc` + 1개 `mux.Handle("/")` = 60개**.
스텁·TODO·플레이스홀더 핸들러는 **이 파일에 하나도 없다.**

등록 형식은 두 갈래다: **39개는 경로만**(메서드는 핸들러 내부 검사 또는 미검사), **21개는 `METHOD /path/{id}` 패턴**.

| 경로 | 줄 | 종단 |
|---|---|---|
| `/api/stats` | 92 | `stats()` @878 |
| `/api/findings` | 93 | `finding.ByProject` |
| `/api/scanruns` | 94 | `scanengine.RunsByProject` |
| `/api/coverage` | 95 | `coverage.Report` |
| `/api/endpoints` | 96 | `endpoints.Targets` |
| `GET /api/proxy` | 98 | `proxyStatus` (이슈 #5) |
| `POST /api/proxy/capture` | 99 | `proxyCaptureHandler` — `proxy:control` 리더·감사 (이슈 #5) |
| `/api/crawl` | 97 | `crawlHandler` @555 |
| `/api/crawl-modes` | 98 | `crawler.HeadlessAvailable` |
| `/api/scan` | 101 | `scanHandler` @308 |
| `POST /api/scanruns/{id}/{pause,resume,cancel}` | 102-104 | `scanControl` @495 |
| `/api/traffic` | 105 | `traffic.Recent(50)` |
| `/api/rules` | 106 | `rules.Snapshot` |
| `/api/detectors` | 107 | `detector.Catalog` |
| `/api/payloads` | 108 | `payload.Info` |
| `/api/llm-decisions` | 109 | `llm.Decisions` |
| `/api/rule-candidates` | 110 | `advisor.Candidates` |
| `/api/rules/adopt` | 111 | `ruleAdoptHandler` @337 |
| `/api/checkitems` | 112 | `checklist.Current().CheckItems` |
| `/api/projects` | 113 | `projectsHandler` @671 |
| `/api/activate-project` | 114 | `activateHandler` @779 |
| `/api/project-credentials` | 115 | `credentialsHandler` @830 |
| `/api/active-project` | 116 | `project.Active` |
| `GET /api/projects/{id}/{findings,scanruns,coverage,report,credentials}` | 121-145 | 인라인 + `requireAccess` |
| `POST /api/projects/{id}/members[/remove]` | 152-153 | `memberAdd/RemoveHandler` @740/@762 |
| `/api/tenants` | 155 | `tenant.List` |
| `POST /api/tenants/{id}/{start,stop}` | 156-157 | @709/@728 |
| `GET /api/tenants/{id}/{endpoints,traffic}` | 158-165 | 인라인 + `requireAccess` |
| `POST /api/findings/{id}/status` | 173 | `findingStatusHandler` @635 |
| `POST /api/findings/clear` | 174 | `clearFindingsHandler` @586 |
| `GET /api/projects/{id}/bundle` | 176 | `bundleDownload` @598 |
| `/api/import-bundle` | 177 | `importBundleHandler` @610 |
| `/api/artifact-ext` | 178 | `bundle.Ext` |
| `/api/me` | 180 | 사용자 + 권한 |
| `/api/users` | 184 | `usersHandler` @376 |
| `POST /api/users/{id}/{delete,password}` | 185-186 | @414/@443 |
| `/api/audit` | 187 | `audit.List` |
| `/audit.csv` | 188 | `auditCSV` @922 (UTF-8 BOM) |
| `/api/login`, `/api/logout` | 189-190 | @239/@269 |
| `/api/reverify` | 191 | `reverifyHandler` @523 |
| `GET /api/scan-diff` | 192 | `scanDiff` @911 |
| `/api/report`, `/api/evidence` | 193, 196 | `report.Rows`/`EvidenceRows` |
| `GET /report.xlsx`, `/coverage.xlsx` | 199-200 | @902/@935 (실제 excelize 스트림) |
| `/api/auth` | 201 | `authSummary` @944 |
| `/api/login-seq` | 202 | `loginSeqHandler` @473 |
| `/api/schemes` | 203 | `checklist.Schemes/Selected` |
| `/` | 207 | `spaHandler()` @994 — **embed 대상 부재로 컴파일 불가** |

**라우트 설계상 짚을 점:**
- 경로만 등록된 라우트 다수가 실제로는 메서드 의존적으로 동작한다. 예컨대 `/api/users`(:184)는 POST가 아닌 모든 메서드에 목록을 반환하므로 `DELETE /api/users`가 조용히 목록을 돌려준다. `/api/reverify`(:191), `/api/crawl`(:97), `/api/login-seq`(:202)도 같다.
- **`GET /api/projects/{id}/bundle`(:176)은 형제 라우트들과 달리 `requireAccess`도 `authorize`도 호출하지 않는다.** `bundleDownload`(`webui.go:598-607`)는 곧바로 `bundle.Export(r.PathValue("id"))`를 부른다. `withAuth`의 세션 검사만 걸리므로 **인증된 아무 분석가나 임의 프로젝트를 통째로 내보낼 수 있다.**
  (참고: `POST /api/findings/clear`(:174)와 `POST /api/users/{id}/delete`(:185)는 mux 패턴에 메서드 접두사가 있어 Go 1.22+ ServeMux가 메서드를 강제하며, 핸들러도 `authorize`로 권한을 검사한다. 이쪽은 문제없다.)

### 4.3 MCP 서버 — 툴 56개

HTTP 라우트가 아니라 단일 엔드포인트다: `mcp.NewStreamableHTTPHandler`를 `local.MCPAddr`(기본 `127.0.0.1:8765`)에 바인딩. 툴 56개 전부 실제 본체를 갖는다 — `run_scan`, `set_project_credentials`, `export_project`, `create_project`, `add_project_member`, `kill_switch`, 그리고 이슈 #5로 추가된 `proxy_status`·`set_capture`(공용 프록시 캡처 상태·토글) 등. (개수는 이슈 #5의 2개 추가로 54→56이 됐고, `@줄` 참조는 §0 갱신 2의 밀림을 감안할 것.)

**보안상 중대한 비대칭:** MCP 표면에는 **인증이 전혀 없다.** `webui`는 `withAuth` 미들웨어(`webui.go:214`)로 세션을 강제하지만, MCP는 `http.ListenAndServe(addr, handler)`에 핸들러를 그대로 물린다. 게다가 `authz()`(`mcpserver.go:758-759`)는 **프로세스 전역** `user.Current()`로 신원을 해석하는데, `user.Seed()`(`user/user.go:122`)가 이를 `leader`로 초기화한다. → **`:8765`에 도달할 수 있는 클라이언트는 누구나 리더 권한으로 행동한다.** 기본 바인딩이 `127.0.0.1`인 것만이 유일한 방어다. 추가로 `export_project`/`import_project`는 툴 인자로 받은 **임의 파일시스템 경로를 검증 없이** 사용한다(`mcpserver.go:307` `os.WriteFile(path, ...)`, `:321` `os.ReadFile(args.Path)`).

> **추정**: `webui.go:231`에 "요청별 신원 (전역 덮어쓰기 없음 → 동시 사용자 격리)" 주석과 함께 이루어진 리팩터링이 MCP 경로에는 적용되지 않은 것으로 보이며, 의도된 비대칭이 아니라 누락으로 읽힌다.

### 4.4 기타 라우트

- **`cmd/vulnapp`** — 21개 엔드포인트(`127.0.0.1:9099`). 각 취약점과 그 안전 대조군이 쌍을 이룬다(`/report`↔`/report-safe`, `/user`↔`/user-safe`, `/upload`↔`/upload-safe`, `/go`↔`/safe-go`). 미들웨어 `noSecurityHeaders`(`main.go:333`)는 의도된 no-op. 전부 실제 동작.
- **`internal/vulnlab`** — 6개 라우트(`/exec`, `/fetch`, `/greet`, `/login`, `/comment`, `/xml` — `vulnlab.go:22-89`). `internal/detector/vulnlab_test.go:17,54`에서만 참조되며 **어떤 바이너리에도 연결되지 않는다.**
- **`internal/tenant`** — `tenant.Start(pid)`(`tenant.go:68`)가 `127.0.0.1:0`(OS 할당 포트, `tenant.go:82`)에 테넌트별 `proxyengine.NewFor(...)` 프록시를 띄운다. 실제 동작.

---

## 5. 데이터 흐름 — UI → API → 저장소

### 5.1 전체 그림

```
[UI]            ✗ 전부 부재 (화면 0개, api.ts는 데드코드)
                     ↓  ← 여기가 완전 단절
[HTTP API]      ✓ 58개 라우트, 전부 실제 로직  ┐
                     ↓                          ├ 단, cmd/proxy가 빌드되지 않아
[비즈니스 로직]  ✓ 11,256줄, 스텁 0개           ┘   런타임에는 아무것도 도달 불가
                     ↓
[영속화]        ◐ JSON 파일 (DB 없음), 절반은 재시작 시 소실
```

**프론트가 실제로 호출하는 엔드포인트: 0개.** `api.ts`에는 경로 리터럴이 하나도 없다(`grep '/api'` 결과 0건) — 경로를 인자로 받는 범용 헬퍼뿐이다. 구체적 경로를 넘길 호출자는 부재하는 `main.tsx`/컴포넌트에 있었을 것이다.

### 5.2 기능 수직별 매트릭스

✓ 실제 · ◐ 부분/휘발성 · ✗ 부재

| 기능 | UI | 라우트 | 로직 | 영속화 |
|---|---|---|---|---|
| **프로젝트 관리** (`project`) | ✗ 타입만 (`api.ts:173`) | ✓ `webui.go:113-153` | ✓ CRUD + ACL + AES-256-GCM 인증정보 (`secret.go:48`) | ✓ `projects.json` (`project.go:102`) |
| **스캔** (`scanengine`/`detector`/`payload`) | ✗ 타입만 (`api.ts:47`) | ✓ `webui.go:101-104` | ✓ 탐지기 26종, goroutine 잡 + 일시정지/재개/취소 (`scanengine.go:112-175`) | ✓ `findings.json` + `scanruns.json` |
| **프록시/트래픽** (`proxyengine`/`traffic`/`ca`) | ✗ 타입조차 없음 | ✓ `webui.go:105` (읽기 전용) | ✓ goproxy MITM, scope→rule→llm 파이프라인 (`proxy.go:28,93,118`) | ◐ 엔드포인트는 `endpoints.json`, **트래픽은 200개 RAM 링버퍼 → 재시작 시 소실** (`traffic.go:10`) |
| **정찰/크롤** (`crawler`/`endpoints`/`scope`) | ✗ 타입만 (`api.ts:207`) | ✓ `webui.go:97` | ✓ 정적 + chromedp 헤드리스 | ◐ 크롤 **실행 이력은 RAM** (`crawler.go:57-62`), 발견 엔드포인트는 디스크 |
| **취약점/이행점검** (`finding`/`reverify`) | ✗ 타입만 | ✓ `webui.go:173,174,191,192` | ✓ 상태머신(`finding.go:119`) + 낙관적 락(`webui.go:649-665`) + HTTP replay | ◐ finding ✓ / **이행점검 실행 이력 RAM only** (`reverify.go:52-56`) |
| **리포트** (`report`/`bundle`) | ✗ 다운로드 UI 없음 | ✓ `webui.go:176,177,193,196,199,200` | ✓ excelize 11컬럼 + 증적 시트 (`report.go:154-211`) | ✓ 온디맨드 생성 |
| **점검항목/커버리지** (`checklist`/`coverage`) | ✗ 타입만 (`api.ts:59-90`) | ✓ `webui.go:95,112,203` | ✓ 3계층 매핑 + 시드 | ◐ 항목표 ✓ `checklist.config.yaml` / **선택 스킴 RAM only** (`checklist.go:61`) |
| **LLM 어드바이저** (`llm`/`advisor`/`rules`) | ✗ 타입만 (`api.ts:122,149`) | ✓ `webui.go:109-111` | ✓ 4개 프로바이더 + 시그니처 클러스터링 | ◐ **판단 로그·후보 RAM only** (`llm.go:79`) / 채택 룰 ✓ `rules.adopted.json` |
| **MCP** (`mcpserver`) | — | ✓ 자체 서버 (webui mux와 별개) | ✓ 툴 56종 | 위 저장소들을 그대로 사용 |
| **인증/사용자/테넌트** (`auth`/`user`/`tenant`/`session`) | ✗ **로그인 폼조차 없음** | ✓ `webui.go:155-157,180-190` | ✓ bcrypt + RBAC + 요청별 신원 | ◐ 사용자 ✓ `users.json` / **세션·테넌트 RAM only** → 재시작 시 전원 로그아웃, 테넌트 프록시 소멸 |

### 5.3 영속화 실태 — DB 없음, JSON 파일

**디스크에 저장되고 기동 시 복원되는 것** (`cmd/proxy/main.go:107,116,135-137`, `:61`에서 복원):

| 데이터 | 파일 | 쓰기 | 읽기 |
|---|---|---|---|
| 도출항목 | `findings.json` | `finding.go:81` | `finding.go:87` |
| 사용자(+bcrypt 해시) | `users.json` | `user.go:121` | `user.go:95` |
| 프로젝트(+활성 id) | `projects.json` | `project.go:102` | `project.go:76` |
| 스캔 실행 | `scanruns.json` | `scanengine.go:290` | `scanengine.go:296` |
| 공격면 | `endpoints.json` | `endpoints.go:549` | `endpoints.go:557` |
| 채택 룰 | `rules.adopted.json` | `rules.go:147` | `rules.go:132` |
| CA 인증서/키 | `ca.crt`(0644) / `ca.key`(0600) | `ca.go:76`, `:86` | `ca.go:96,100` |
| AES 마스터 키 | `secret.key`(0600) | `secret.go:58` | `secret.go:48` |
| 설정 | `local.config.yaml`, `project.config.yaml`, `checklist.config.yaml` | `config.go:106`, `checklist.go:220` | `config.go:102`, `checklist.go:215` |

**재시작 시 소실되는 것 (인메모리 전용):**
로그인 세션(`session.go:24-26`), 최근 트래픽(`traffic.go:21-23`, 200개 상한), 크롤 실행(`crawler.go:57-58`), 이행점검 실행(`reverify.go:52-53`), LLM 판단 로그(`llm.go:80`), 테넌트 프록시(`tenant.go:45-47`, 포트도 OS 할당이라 매번 바뀜), 테넌트별 엔드포인트 트리·트래픽(`endpoints.NewTree()`가 `name:""`로 생성 → 덤프 안 함, `endpoints.go:75`).

**쓰기 전용 — 디스크에 쓰지만 절대 읽지 않는 것 (실질적 버그):**

- **`internal/audit`** — `Record()`가 `audit.json`을 쓰지만(`audit.go:44`), **패키지에 `Load()`가 아예 없다** (`grep -c "func Load" = 0`; 노출 함수는 `Record`/`List`/`Reset` 셋뿐). 인메모리 `log` 슬라이스가 nil로 시작하므로, **재시작 후 첫 `Record()` 호출이 `audit.json`을 1건짜리 배열로 덮어쓴다.** `/api/audit`(`webui.go:187`)과 `/audit.csv`(`webui.go:922`)는 둘 다 인메모리 슬라이스를 읽는다. `webui.go:921`이 이 파일을 "규제 제출용 증적"으로 문서화하고 있음을 감안하면 **감사 추적이 재시작마다 조용히 파괴되는 실질적 결함**이다.
- **`internal/profile`** — `Save()`가 `profiles.json`을 쓰지만(`profile.go:32`) `Load()`가 없다. 같은 형태의 문제.

**CWD 위험:** 위 파일명이 전부 맨 상대 경로다(`finding.go:16` `const file = "findings.json"`, `scanengine.go:285`, `profile.go:32`, `audit.go:22`). **상태가 프로세스를 시작한 디렉터리에 종속된다** — 다른 디렉터리에서 실행하면 조용히 빈 상태로 시작한다.

> 이 감사 중 `go test ./...`를 돌리자 `findings.json`·`endpoints.json`·`scanruns.json`·`profiles.json`이 7개 패키지 디렉터리에 실제로 흩뿌려졌다(정리 완료). 일부 테스트는 `os.Remove`로 뒷정리를 하지만(`finding/persist_test.go:11,44`, `bundle/bundle_test.go:19`) 전부는 아니다.

### 5.4 고아 코드 / 산출물

**완전한 고아 (비테스트 import 0건):**
- **`internal/vulnlab`** (145줄) — 어떤 HTTP 라우트도, 어떤 `cmd` 바이너리도 도달하지 않는다. `internal/detector/vulnlab_test.go`만 사용한다. 테스트 픽스처로서는 정상적인 위치다.

**`webui`를 통해서만 도달 가능 → 빌드 실패로 현재 도달 불가:**
`internal/crawler`(유일한 비테스트 import가 `webui.go:28`), `internal/session`(`webui.go:40`), 그리고 `reverify`·`advisor`·`bundle`·`report`·`coverage`·`audit`(import가 `webui` + `mcpserver`뿐이며, `mcpserver`도 `cmd/proxy`에서만 기동됨 — `main.go:163`).

**고아 YAML 4개 — `docs/*.yaml`은 백엔드가 소비하지 않는다.**

| 파일 | 항목 수 |
|---|---|
| `docs/vulndefs.yaml` | VulnDef 65 |
| `docs/checkitems.kii.yaml` | 21 (주요정보통신기반시설) |
| `docs/checkitems.fin.yaml` | 48 (전자금융) |
| `docs/checkitems.mobile.yaml` | 13 (모바일) |

세 가지 독립적 근거로 확인했다:

1. **파일명 참조 0건.** `grep -rn "vulndefs" backend/` → 0건. `checkitems` 매치 4건은 전부 무관하다(구조체 yaml 태그 `checklist.go:53`, REST 라우트 `webui.go:112`, MCP 툴명 `mcpserver.go:475`·`cmd/mcpclient/main.go:70`). **`docs/` 경로를 읽는 코드가 없다.**
2. **런타임은 다른 파일을 쓴다.** `cmd/proxy/main.go:75`가 `checklist.LoadOrCreate("checklist.config.yaml")` — **CWD의** 파일을 읽고, 없으면 `internal/checklist/seed.go`의 하드코딩 데이터로 생성한다.
3. **스키마가 호환되지 않아, 경로를 맞춰줘도 로드에 실패한다.**
   - 최상위 키 불일치: Go는 `vulns:`를 기대(`checklist.go:53`)하지만 `docs/vulndefs.yaml:2`는 `vulndefs:`.
   - **타입 불일치(결정적):** Go `CheckItem.Vuln`은 **스칼라 `string`**이다 — `checklist.go:45`:
     ```go
     Vuln    string `yaml:"vuln" json:"vuln"`  // 2층 VulnDef id
     ```
     그러나 `docs/checkitems.kii.yaml:6-12`의 `vuln:`은 **리스트**다(`- vuln.os-command` 외 5개).
   - 미지원 키: `통합: true`, `상세설명:`, `context:`에 대응하는 Go 필드가 없다. 반대로 Go의 `평가항목`(`checklist.go:44`)은 YAML에 없다.

   > `vuln[]` 배열(1:N 결합)은 `spec.md:274-275,301`이 핵심 설계로 강조한 기능인데, **Go 구현은 스칼라 단일 참조로 축소**되어 KII-01 같은 1:N 통합 항목을 스펙대로 표현할 수 없다. **추정**: 대신 `VulnDef.Detectors []string`(`checklist.go:36`)로 우회한 것으로 보인다.

4. **데이터도 드리프트했다.** 런타임 소스인 `seed.go`와 docs YAML의 개수가 다르다:

   | 스킴 | `seed.go` (런타임) | `docs/*.yaml` |
   |---|---|---|
   | 주요정보통신기반시설 | 21 | 21 ✓ |
   | 전자금융 | 66 | 48 ✗ |
   | 모바일 | 1 | 13 ✗ |
   | VulnDef | 33 | 65 ✗ |

### 5.5 프론트엔드 서빙 방식

Go가 단일 바이너리로 서빙하도록 **의도**되어 있다:
- `webui.go:46` — `//go:embed all:dist` → `var distFS embed.FS`
- `webui.go:207` — `mux.Handle("/", spaHandler())`
- `webui.go:994-1007` — `fs.Sub(distFS, "dist")` + `http.FileServer`, SPA 폴백은 `index.html`(`:1001-1004`)

별도 dev 서버 설정은 커밋되어 있지 않고(`vite.config.ts` 없음), `package.json:7`의 `"dev": "vite"`도 `main.tsx` 부재로 실패한다.
또한 `spaHandler()`는 embed 서브트리가 없으면 `log.Fatalf`(`webui.go:997`)로 **프로세스 전체를 죽인다** — 에러 반환이 아니다.

`README.md:63`과 `docs/00-아키텍처.md:175`는 프론트 빌드 출력이 `backend/internal/webui/dist`라고 명시하지만, 그 경로는 `vite.config`의 `build.outDir` 설정으로만 달성 가능하고 그 파일이 없다 → 기본값 `frontend/dist`로 나간다. **문서와 불일치.**

### 5.6 인증 흐름 실태

`webui` 표면의 인증·인가는 **실제로 구현되어 있고 품질도 준수하다.**

**미들웨어** — `webui.go:214-236` `withAuth`, `webui.go:210`에서 적용:
- 허용 목록은 정확히 한 경로: `{"/api/login": true}` (`:215`)
- `/api/` 이하 전부 유효한 `cg_sid` 쿠키 → `session.UserID` 요구(`:224-226`), 없으면 `401 인증 필요`(`:228`)
- 해석된 사용자는 **전역이 아니라 request context**에 담긴다(`:234`). `:231` 주석이 동시 사용자 격리를 명시적으로 언급한다.
- **우회 경로:** `authDisabled`(`:220`) — `local.config.yaml`의 `auth_disabled`로 설정(`config.go:36`), `cmd/proxy/main.go:166`에서 배선, `:169`에서 경고 로그. 기본값은 off.

**인가** — `webui.go:297-305` `authorize(w, r, action, target)`: `user.Can(role, action)`로 RBAC 검사(권한 테이블 `user/user.go:34`), 거부 시 감사 로그 기록. 추가로 프로젝트별 ACL `canAccess`/`requireAccess`(`:72-86`)가 `project.IsMember`를 쓴다.

**보호된 라우트 추적 예 — `POST /api/scan`:**
1. `withAuth`(:219) → `cg_sid` 쿠키 → `session.UserID`(`session.go:39`, 인메모리 맵 + 8시간 TTL) → `user.Get(uid)` → context
2. `scanHandler`(:308) 메서드 가드(:310)
3. `authorize(w, r, "scan:run", "scan")`(:313) → 실패 시 403 + `audit.Record(..., "denied")`
4. `endpoints.Targets()`(:323), 비면 400(:325)
5. `scanengine.Start(...)`(:328) → 잡 goroutine(`scanengine.go:112`) → `d.Detect(...)` → `finding.Add(f)`(`scanengine.go:170`) → `findings.json`
6. `audit.Record(..., "ok", ...)`(:330) → `audit.json`

**구멍은 두 곳이다:** §4.3의 MCP 무인증, 그리고 §4.2의 `GET /api/projects/{id}/bundle` ACL 누락.

---

## 6. 점검항목 자동화 실태

`internal/checklist/seed.go`가 런타임 기본 데이터의 유일한 출처다. 실측:

- **VulnDef 33개** 중 **`Detectors:` 매핑을 가진 것은 19개** → **14개는 자동탐지 없이 수동**이다. `Detectors`가 비어 있는 것이 곧 "수동/미지원" 인코딩이다(`checklist.go:36` 주석).
- **CheckItem 88개** — 전자금융 66 / 주요정보통신기반시설 21 / 모바일 1. (`Detectors`는 CheckItem이 아니라 VulnDef에 달린다.)
- 모바일 스킴은 항목이 **1개뿐**으로, `spec.md:167`의 "FR-2.8 잠정 — 방향성만 정의"와 일치한다.

전 백엔드에서 `TODO|FIXME|미구현|not implemented` 검색 결과는 **단 2건**이며, 둘 다 코드 스텁이 아니라 위 "수동 점검" 표기다(`seed.go:71`, `checklist.go:36`). **`panic(`은 비테스트 코드에 0건, 빈 함수 본체도 0건이다.**

---

## 7. 발견된 주요 이슈 (우선순위순)

| # | 이슈 | 근거 | 영향 |
|---|---|---|---|
| 1 | **빌드 불가** — `//go:embed all:dist` 대상 부재 | `webui.go:46` | 제품 본체 `cmd/proxy`를 만들 수 없음 |
| 2 | **프론트엔드 전체 부재** — 엔트리 `main.tsx` 없음, 화면 0개 | `frontend/index.html:10` | 58개 라우트에 소비자가 없음. HITL 원칙(`spec.md:215,322`)을 UI 없이 강제할 수 없음 |
| 3 | **감사 로그가 재시작마다 파괴** — `audit.json`을 쓰지만 읽지 않음 | `audit/audit.go:25-44` (`Load()` 부재) | 규제 제출용 증적 소실. `profile`도 동일 형태 |
| 4 | **MCP 표면 무인증 + 전역 리더 권한** | `mcpserver.go:717-719`, `:758-759` | `:8765` 도달자는 누구나 리더. `export_project`/`import_project`는 임의 경로 R/W (`:307`, `:321`) |
| 5 | **`GET /api/projects/{id}/bundle` ACL 누락** | `webui.go:176`, `:598-607` | 인증된 아무 분석가나 임의 프로젝트 전체 내보내기 가능 |
| 6 | **상태 경로가 전부 CWD 상대** | `finding.go:16`, `scanengine.go:285`, `audit.go:22` 외 | 다른 디렉터리에서 실행 시 조용히 빈 상태로 시작 |
| 7 | **외부 공격면 두 패키지에 테스트 0** | `webui`(1,017줄), `mcpserver`(797줄) | 코드의 12.5%이자 공격면 100% |
| 8 | **HTTP 에러 응답 형식 불일치** | 평문 `http.Error` vs 유일한 JSON 바디 `webui.go:653-655` | 프론트가 에러를 일관되게 파싱 불가 |
| 9 | **`docs/*.yaml` 4개가 고아 + 스키마 비호환** | `checklist.go:45` vs `checkitems.kii.yaml:6-12` | 설계 산출물과 런타임 데이터가 분기됨 |
| 10 | **`.gitignore` 부재** | 레포 전체 | `ca.key`·`secret.key`·`users.json` 실수 커밋에 대한 방어 없음 |

**문서 자체의 부정확성:**
- `docs/00-아키텍처.md:10-16`이 상위 폴더 `../`에 있다고 기술한 한글 설계 문서 3개가 레포에 없다(부모 디렉터리에 `AVA`만 존재함을 확인). **추정**: 첫 번째는 `docs/spec.md`와 동일 내용으로 보인다.
- `spec.md:290`이 참조하는 `항목_매핑_초안.md`도 부재.
- `README.md:61`, `docs/00-아키텍처.md:173,181`의 경로 `proxy-poc/frontend`, `proxy-poc/backend`가 실제 구조(`AVA/...`)와 다르다. **추정**: 레포명 변경 후 문서 미갱신.
- `docs/00-아키텍처.md:187`의 "`npm run dev`(Vite :5173, `/api` 프록시)"는 `vite.config` 부재로 성립하지 않는다.

---

## 8. 강점 (공정을 기하여)

- **미사용 직접 의존성 0개.** 8/8 전부 실사용 — 이례적으로 깔끔하다.
- **스텁·`panic`·빈 함수 0개.** "껍데기"는 프론트지 백엔드가 아니다.
- 모든 노출 심볼에 **스펙 추적 가능한 한글 doc 주석**(`FR-x.y`, `§x.y`)이 일관되게 붙어 있다.
- 인터페이스 3개, 전부 **소비자 측 선언** — 올바른 Go 스타일.
- finding의 **낙관적 락 + 검토 상태머신**(`finding.go:114-119`, `webui.go:649-665`)은 제대로 구현되어 있다.
- **AES-256-GCM 인증정보 암호화**(`secret.go:48`), **bcrypt 인증**(`user.go:14`), 요청별 신원 격리(`webui.go:231`).
- 테스트를 가진 **21개 패키지 전부 통과**, 실패 단언 0건. 탐지기는 실제 TLS 서버를 띄워 통합 검증한다.
  (전체 35개 패키지 중 14개는 `_test.go`가 없다 — §1.2의 "test 0" 항목.)
