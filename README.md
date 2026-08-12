# AVA — LLM 기반 웹 취약점 진단 도구 (Automated Vulnerability Assessment)

Go(goproxy) **MITM 프록시 엔진**을 코어로, 그 위에 **MCP 오케스트레이션 계층**과
**React 웹 GUI**를 얹은 LLM 기반 웹 취약점 진단 도구입니다. 프론트를 `go:embed`로 넣어
**단일 실행 바이너리**로 배포됩니다. 주요정보통신기반시설·전자금융 규제 점검항목표에 맞춘
자동 진단 → 도출리스트/점검결과표(xlsx) → 이행점검까지 전 워크플로우를 커버합니다.

| 구성 | 포트 | 역할 |
|---|---|---|
| **프록시** | `:8080` | HTTPS 가로채기(MITM) + 스코프 강제 + 인증 주입 + 판단 파이프라인 + 마스킹 + 공격면 캡처 |
| **MCP** | `:8765` | 외부 LLM 에이전트/번들 클라이언트가 라이브 프록시를 조회·제어 (StreamableHTTP) |
| **웹 GUI** | `:8090` | 진단 현황·취약점·증적·커버리지·리포트 (다크 기본, 테마 토글) |

---

## 한눈에

- **탐지기 25종**(내장 23 + 외부도구 2) — XSS 3형태·SQLi 3종·인젝션 계열(cmd/SSRF/XXE/SSTI/LDAP/SSI)·접근통제·설정 점검. 규제 점검항목에 매핑돼 **수동 항목 최소화**
- **판단 파이프라인** — 스코프(hard) → Rule(결정론) → LLM(애매한 요청만) → 전송+캡처. 스코프 밖으로 아무것도 내보내지 않음
- **자동 공격면 탐색** — 링크·폼·JS 번들을 따라가는 크롤러(정적/헤드리스 옵트인) + 프록시 수동 캡처
- **증적 기반** — 각 finding에 재현 요청·증명 응답(민감값 마스킹)·상태코드
- **규제 산출물** — 도출리스트 11컬럼 xlsx(+증적 시트) · 점검결과표(양호/취약/미점검) · 감사 CSV
- **멀티테넌시·RBAC·영속화** — 프로젝트별 격리 프록시, 리더/수행원 권한, bcrypt 로그인, 인증정보 AES-256-GCM 암호화, 재시작 넘어 데이터 유지

---

## 문서 안내

이 README는 **표지·요약**입니다. 각 기능의 상세는 웹 GUI 좌측 내비게이션과 1:1로 대응하는
`docs/` 문서를 참고하세요.

> **브라우저로 한 번에 보기:** [`docs/index.html`](docs/index.html)을 더블클릭하면 아래 문서 전체를
> 사이드바 탐색·다크모드가 있는 단일 페이지로 볼 수 있습니다(서버·인터넷 불필요, 오프라인 열람 가능).
> 이 파일은 **`.md`에서 자동 생성**됩니다 — 직접 편집하지 말고 `.md`를 고친 뒤 `node docs/build.mjs`로 재생성하세요.

### 설계·운영
- [docs/00-아키텍처.md](docs/00-아키텍처.md) — 설계 배경, goproxy 선택, 2계층 구조, 판단 파이프라인, 프로젝트 구조, 빌드·실행, 알려진 한계, 함정, 성숙도

### 화면별 기능 (사이드바 순서)
| 그룹 | 페이지 | 문서 |
|---|---|---|
| 작업공간 | 개요 | [docs/01-개요.md](docs/01-개요.md) |
| 작업공간 | 프로젝트 | [docs/02-프로젝트.md](docs/02-프로젝트.md) |
| 진단 | 정찰(대상 파악) | [docs/03-정찰.md](docs/03-정찰.md) |
| 진단 | 스캔(자동화 진단) | [docs/04-스캔.md](docs/04-스캔.md) |
| 결과 | 취약점 | [docs/05-취약점.md](docs/05-취약점.md) |
| 결과 | 커버리지 | [docs/06-커버리지.md](docs/06-커버리지.md) |
| 결과 | 리포트 | [docs/07-리포트.md](docs/07-리포트.md) |
| 결과 | 이행점검 | [docs/08-이행점검.md](docs/08-이행점검.md) |
| 인텔리전스 | 룰 제안 | [docs/09-룰제안.md](docs/09-룰제안.md) |
| 인텔리전스 | 감사 | [docs/10-감사.md](docs/10-감사.md) |
| 관리 | 사용자 | [docs/11-사용자.md](docs/11-사용자.md) |

---

## 빠른 실행

프론트를 먼저 빌드해야 합니다(출력이 Go 바이너리에 embed됨):

```bash
cd frontend
npm install            # 최초 1회
npm run build          # → backend/internal/webui/dist (embed)
```

> `backend/internal/webui/dist`는 빌드 산출물이라 커밋되지 않습니다.
> `go build` 전에 반드시 위 프론트 빌드를 먼저 수행하세요. 건너뛰면
> `pattern all:dist: no matching files found` 로 컴파일이 실패합니다.

백엔드 빌드 & 실행:

```bash
cd proxy-poc/backend
go build -o proxy-poc.exe ./cmd/proxy    # 프록시(:8080) + MCP(:8765) + 웹(:8090)
./proxy-poc.exe                          # 최초 실행 시 ca.crt/ca.key 생성
```

웹 GUI: **http://127.0.0.1:8090** — 데모 계정 `leader / leader123`, `analyst / analyst123`.
프록시로 트래픽을 흘려 공격면을 채운 뒤 스캔합니다(상세는 [docs/00-아키텍처.md](docs/00-아키텍처.md) 참고):

```bash
curl.exe -sk -x http://127.0.0.1:8080 "https://httpbin.org/get?user=admin&password=secret" -o NUL
```

빌드·CA 신뢰·브라우저 프록시 경유·설정(YAML)·테스트 등 전체 절차는
[docs/00-아키텍처.md](docs/00-아키텍처.md)에 정리돼 있습니다.

---

## 현황 (요약)

전 워크플로우가 end-to-end로 도는 **잘 설계된 PoC**입니다. 아키텍처(멀티테넌시·영속화·RBAC·
암호화·증적·커버리지)는 견고하며, 인젝션 계열 자동화(SQLi·XSS·cmd·SSRF·XXE·SSTI·LDAP·SSI)는
실앱(DVWA + 자체 vulnlab)으로 정탐 검증했습니다. 정밀도·커버리지·LLM 엔진(대형 모델 연동)·실운영
하드닝은 계속 고도화 중입니다. 자세한 성숙도·로드맵은 [docs/00-아키텍처.md](docs/00-아키텍처.md)의
"성숙도 & 다음 단계"를 참고하세요.

> **민감 파일(공유/커밋 금지):** `ca.key`, `secret.key`, `users.json`, `projects.json`.
> `local.config.yaml`은 PC 전용(키 보관), `project.config.yaml`은 공유 가능(스코프·룰).
