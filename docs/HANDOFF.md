# HANDOFF — 인수인계

> 대상 브랜치: `claude/repo-codebase-audit-qy91vo` · PR [#2](https://github.com/Vornsk/AVA/pull/2) · 기준 시점 2026-08-10
>
> **이 문서는 프로젝트 맥락을 전혀 모르는 사람을 전제로 쓰였다.**
> 모든 수치에 재현 명령이나 `파일:줄` 근거를 붙였다. 실행으로 확인하지 않은 판단은 **추정**으로 표시했다.

---

## §0. 갱신 블록 (2026-08-18) — **먼저 읽을 것**

이 문서의 본문은 **2026-08-10, 브랜치 `claude/repo-codebase-audit-qy91vo`(PR #2) 시점의 스냅샷**이다.
그 뒤로 백엔드가 계속 바뀌었으므로 **본문의 수치·줄번호는 그대로 믿으면 안 된다.**
아래가 현재(브랜치 `seona`, `8e9586b`) 기준으로 재측정한 갱신분이다.

### 무엇이 뒤집혔나

| 본문 | 지금 |
|---|---|
| §1.3 "**백엔드 `.go` 를 한 번도 건드리지 않았다**" | **더는 사실이 아니다.** 그 브랜치의 diff에 한해 참이었을 뿐, 이후 이슈 #6·#22·#23·#31·#24 가 백엔드를 바꿨다 |
| §3 ③ 베이스라인 표 | 아래 표로 대체 |
| §3 ④ "`webui`·`mcpserver`·`audit` 에 테스트가 0개" | `webui` 는 **2개 생겼다**(`endpoints_test.go`·`projects_delete_test.go`). `mcpserver`·`audit` 은 **여전히 0개** |
| §3 ② "`.github/` 에 ISSUE_TEMPLATE 3종 + `PULL_REQUEST_TEMPLATE.md` + `config.yml`" | 현재 `.github/` 에는 `ISSUE_TEMPLATE/` 4종만(`bug_report`·`detector_report`·`feature_request`·`config`). **PR 템플릿은 없다** |
| §4 2번 `bundleDownload` 위치 `webui.go:598-607` | **`webui.go:622-631` 로 이동**. ACL 누락은 **그대로 미해결** |

### 재측정 베이스라인 (§3 ③ 표 대체)

| 항목 | 본문 값 | **현재 값** | 재현 명령 |
|---|---|---|---|
| 전체 Go 패키지 | 35 | **37** | `cd backend && go list ./... \| wc -l` |
| 테스트 보유 패키지 | 21 | **25** | `git ls-files \| grep '_test\.go$' \| xargs -n1 dirname \| sort -u \| wc -l` |
| `go test ./...` | ok 21 | **전 패키지 통과 (FAIL 0)** | `cd backend && go test ./...` |
| 웹 라우트 등록 | 58 | **67** (66 `HandleFunc` + 1 `Handle`) | `grep -c 'mux.HandleFunc' backend/internal/webui/webui.go` |
| MCP 툴 | 54 | **56** | `grep -c 'mcp.AddTool' backend/internal/mcpserver/mcpserver.go` |
| 비테스트 Go LOC | 11,256 | **12,770** | `find backend -name '*.go' ! -name '*_test.go' \| xargs wc -l \| tail -1` |
| 테스트 Go LOC | 3,280 | **4,227** | `find backend -name '*_test.go' \| xargs wc -l \| tail -1` |
| `webui.go` / `mcpserver.go` | 1,017 / 797 | **1,248 / 831** | `wc -l backend/internal/webui/webui.go backend/internal/mcpserver/mcpserver.go` |

### 여전히 유효한 것

- **§4 미해결 항목 4건 전부 그대로다.** MCP 무인증·번들 ACL 누락·`audit.json` 쓰기전용·상대경로 영속화.
  (`grep -c 'func Load' backend/internal/audit/audit.go` → `0`)
- **§3 ② CI 워크플로 부재.** `ls .github/workflows` → 없음. 빌드 순서(프론트 → Go)는 여전히 README 산문으로만 보장된다.
- **§5 환경 제약.** `gh` CLI 없음, Go 1.26.5 고정, 프론트 빌드 선행 필수.
- **§6 실패 모드 4건.** 특히 §6.1(서브에이전트 수치 불일치)·§6.3(`git -C` worktree)은 이후에도 유효한 교훈이다.

### 최근 작업 — 정찰 고도화 (#22 → #24)

정찰(공격면 탐색) 품질을 **숫자로 측정하고 개선하는** 흐름이 붙었다. 순서에 이유가 있다 —
계기판(#22)을 먼저 만들고, 그 계기판으로 개선(#24)의 효과와 회귀를 확인한다.

| 이슈 | 내용 | 산출물 |
|---|---|---|
| #22 | 정찰 벤치 하네스 — ground-truth 대조로 P/R/F1·트리 팽창률 산출 | `backend/internal/recon/bench/`, `docs/recon-groundtruth/` |
| #23 | 정답셋 4종(juice-shop·dvwa·vampi·vulnlab) + 다중 대상 순회 | `docs/recon-groundtruth/*.yaml` |
| #31 | 인증 크롤(세션 주입) — DVWA 재현율 4.0% → 80.0% | `bench.ApplyAuth`, `dvwa.yaml` 로그인 시퀀스 |
| #24 | 경로 정규화 v2 — UUID/hash/date/b64 분류기 + 형제 클러스터링 | `backend/internal/endpoints/normalize.go` |
| #25 | 스펙 인제스터 — robots/sitemap/OpenAPI/GraphQL/소스맵 | `backend/internal/recon/ingest/` |
| #26 | 라이브니스 검증 + 출처 신뢰도 등급 | `backend/internal/recon/liveness/` |
| #27 | 능동 콘텐츠 발견 — embed wordlist + soft-404 재사용 | `backend/internal/recon/discover/` · `probe/` |
| #28 | 정찰 UI — 소스 배지·verified 필터·출처 분포 + UX 개선 | `frontend/src/pages/Recon.tsx` |
| **#38** | **인증 델타 크롤** — 인증 뒤에만 보이는 표면 = 접근통제 진단 후보 | `crawler.runAuthDelta`, `endpoints.authOnly` |
| **#39** | **소스맵 완전 복원** — 파일 단위 프레임워크 라우트 추출 + static-regex 검증 | `ingest.extractFromSources`, `parseSourceMap` |
| **#40** | **파라미터 마이닝** — hidden 파라미터 주입으로 인젝션 포인트 확대(옵트인) | `backend/internal/recon/parammine/`, `endpoints.AddMinedParam` |
| **#41** | **의미 분류** — 경로·파라미터를 auth/payment/admin/pii 등으로 라벨링(룰+LLM) | `backend/internal/recon/classify/`, `endpoints.SetLabels` |

**#24 가 무엇을 바꿨나.** `NormalizePath` 가 숫자-only 세그먼트만 접어서, UUID·해시·날짜 경로가
값마다 별도 노드로 쌓였다(트리 폭발 → 스캔 타겟·커버리지 오염). v2 는 세그먼트를
`{id}`/`{uuid}`/`{hash}`/`{date}`/`{b64}` 로 분류하고, 같은 부모 밑에 값처럼 생긴 리프가
12개 이상 쌓이면 `{slug}` 하나로 접는다. 기존 `endpoints.json` 은 로드 시 1회 재분류·병합한다.

측정 결과(Juice Shop, 전·후 각 4회): **트리 팽창률 headless 1.20x → 1.00x**(목표 ≤1.3 충족),
**static 은 8회 전부 한 칸도 다르지 않음**(P 15.5% / R 41.9% 유지 = 회귀 없음).
상세 표와 재현 절차는 `docs/recon-groundtruth/README.md`, 규칙 설명은 `docs/03-정찰.md`.

**#38 이 무엇을 바꿨나 (확장 로드맵 1번).** 핵심 로드맵(#22~#28) 이후, 기획서 §7 확장의 첫 항목.
로그인 뒤에만 접근되는 표면을 접근통제 진단 후보로 잡는다 — KII·전자금융의 수평/수직 접근통제와 직결.
같은 대상을 비인증→인증 두 패스로 크롤해, **인증 패스에서 2xx 로 접근됐지만 비인증에선 접근 못 한**
경로를 `auth-only` 로 표시한다. "경로 존재"가 아니라 "2xx 접근 성공"이 기준 — 링크는 양쪽에 있어도
401 이면 접근 못 한 것이다. `auth-only` 는 출처 등급이 아니라 직교 플래그(#26 unverified 패턴).

측정(vulnapp 실측): `/orders`·`/profile`·`/dashboard`(비인증 401·인증 200)가 auth-only 로 잡히고,
`/admin`(비인증에도 200, 접근통제 취약)은 auth-only 아님으로 구분됐다. 이 구분이 핵심 —
"숨겨진 표면"과 "인증 없이 뚫리는 표면"은 다르다. 벤치는 `auth-delta` 프로파일(로그인 설정 대상만).

**#39 가 무엇을 바꿨나 (확장 로드맵 2번).** 인제스터는 소스맵을 모으면서 `sourcesContent`를 전부
이어 붙여 `/api·/rest` 정규식 하나만 돌려, 클라이언트 라우트 정의(React/Vue/Angular)를 놓쳤다.
`parseSourceMap`이 이제 `sources`(파일명)와 `sourcesContent`(본문)를 인덱스로 짝지어 파일 단위로
분석한다. 이 위에 네 가지가 올라간다:

- **프레임워크 라우트 추출** — `path:`/`path=` 프로퍼티(`:id`→`{id}`, 상대경로 슬래시 보정,
  와일드카드 절단, 외부URL·보간 제외). 벤더(`node_modules`) 파일은 제외해 라이브러리 `path:` 오탐 차단.
- **자식 라우트 경로 합성**(`composeRoutes`) — 문자열·주석을 건너뛰며 `[`/`]` 깊이와 `children:`
  프리픽스를 추적하는 경량 렉서. `{path:'admin',children:[{path:'users'}]}` → `/admin/users`. 평면
  정규식이면 루트급 `/users`가 돼 라이브니스가 강등하던 재현율 손실을 막는다.
- **설정 상수·내부 URL 추출**(`extractLoosePaths`) — 절대 경로 리터럴과 같은 호스트 URL 경로부.
  정적 에셋(확장자)·외부 호스트는 제외.
- **지연 로딩 청크 추적** — 라우트는 흔히 lazy 모듈(`admin.module.js`)에 있고 index.html 이 아니라
  런타임 번들에서만 참조된다. `sourceMaps`를 워크리스트로 바꿔 번들 JS가 참조하는 `.js` 청크의 `.map`
  까지 따라간다(`maxBundles=40`). 한계: 콘텐츠 해시로 런타임 조립되는 청크명은 못 잡는다(후속).

소스맵 추출물은 정규식 추측이라 `RecordSpec`(면제)이 아니라 `RecordFrom(static-regex)`로 등록해
**라이브니스(#26) 검증 대상**으로 만든다(Juice Shop static 정규식 추출 오탐률 81%를 이 등급 지정이
걸러낸다). 검증은 단위 테스트 위주 — `composeRoutes` 중첩·문자열격리, `extractLoosePaths` 내부/외부
구분, lazy 청크 복원 Run 통합 등. 기존 벤치 3종 무회귀.

**#40 이 무엇을 바꿨나 (확장 로드맵 3번).** 트리는 관측된 요청의 파라미터만 담아, 서버가 처리하지만
노출하지 않는 hidden 파라미터(debug·`admin`·`role`·레거시)를 놓쳤다 — 실제 인젝션·접근통제 진입점이다.
새 `parammine` 모듈이 워드리스트를 검증된 GET 엔드포인트에 주입해 찾는다. 판정은 세 신호(이름/값 반사 —
기준 본문에 없던 것만 · 길이/상태 변화 · 두 값 차등)를 합쳐 정적 반사·soft-404 오탐을 거른다. 효율은
벌크 이분탐색(뭉텅이 주입 → 반응 난 뭉치만 절반씩). 안전장치는 #27 을 그대로 — 옵트인(미옵트인 시 주입
0건, 테스트 보장)·GET only·스코프·예산·감사(`crawl:parammine`). 발견분은 `AddMinedParam` 으로 `mined`
플래그와 함께 붙고 `In=query` 라 `detector.injectable` 이 자동으로 스캔에 포함한다(별도 배선 없음).
검증은 단위 테스트 위주 — 발견·정적 오탐0·반사투성이 방어·예산소진·관측중복 + 크롤러 옵트인. body·header
주입과 소스맵 JS 파라미터명 채굴은 후속.

**#41 이 무엇을 바꿨나 (확장 로드맵 4번).** 정찰은 엔드포인트를 구조(경로·메서드·파라미터)로만 알아,
"결제·관리자·PII 처리인가"라는 의미를 몰랐다 — 규제 매핑(E5)·스캔 우선순위·위험도의 전제다. 새 `classify`
모듈이 라벨(auth·payment·upload·admin·pii·search·api·static)을 붙인다. **룰 우선**(무료·즉시·재현):
경로 세그먼트·파라미터 키를 키워드 사전과 대조해 명백한 것을 확정하고, **의미 라벨을 못 잡은 모호한
경우에만 LLM**(활성 프로바이더 있을 때만). 토큰 절감 — 값·응답은 안 보내고 경로·메서드·키만; 결과는
`(메서드,경로꼴,키)` 시그니처로 캐시(`llm.Judge` 패턴) + 호출 상한. 기존 `llm.Provider.Complete()` 재사용
(`MockProvider` 에 endpoint-classifier 분기 추가). 라벨은 `endpoints.SetLabels` 로 노드에 붙어 출처·
파라미터와 직교하고 `endpoints.json` 에 영속(E5/E6 가 재시작 후 읽음). 크롤 종료 시 자동 분류(수동 단계,
대상 무요청). API `?label=`, Endpoint Tree 민감 라벨 배지. 검증은 단위 테스트 — 대표 경로 28개 룰 매핑,
확정→LLM 스킵, 모호→LLM+토큰절감, 캐시, Run 라벨링, 저장/복원. 실 LLM 평가와 E5 규제 점검항목 연결은 후속.

**#25 가 무엇을 바꿨나.** 링크를 따라가는 크롤만으로는 링크 없는 API 를 찾을 수 없어 VAmPI 재현율이
0% 였다. 인제스터는 대상이 스스로 공개하는 명세를 읽는다 — `/openapi.json` 한 파일이 VAmPI 정답셋
14개를 전부 준다. 크롤 시작 시 1회 자동 인제스트하며, 벤치는 `ingest` 프로파일로 명세만 격리 측정한다.

측정 결과: **VAmPI 재현율 0% → 100%**(ingest 프로파일은 P·R·F1 모두 100%). Juice Shop 은 명세가
없어 `robots.txt` 의 `/ftp` 1건뿐이고 **오탐 0**, DVWA 는 0건에 회귀도 0. 팽창률은 전 대상 1.00x 유지 —
명세 경로(`/users/v1/{username}`)와 크롤 경로(`/users/v1/alice`)가 한 노드로 합쳐지기 때문이다
(#24 의 흡수 메커니즘을 일반화해 재사용).

**#26 이 무엇을 바꿨나.** 크롤러가 JS 번들에서 정규식으로 긁어온 경로에는 실재하지 않는 것이
섞인다(i18n 키·CSS 경로·SPA 클라이언트 라우트). Juice Shop static 은 발견 84건 중 71건(83.5%)이
오탐이었다. 엔드포인트마다 **어디서 알게 됐는지**를 5등급으로 기록하고, 믿을 수 없는 출처
(`crawl-link`·`static-regex`)만 실재를 프로브한다. 실재가 확인되지 않으면 **지우지 않고 강등**한다 —
지우면 왜 제외됐는지 근거가 사라진다.

측정 결과: **juice-shop static 오탐 69 → 28(-59%), 정밀도 18.8% → 36.4%, 재현율 47.1% 그대로.**
dvwa 도 static·headless 둘 다 개선되고 재현율 유지. vampi 는 전부 `spec` 출처라 프로브가 한 건도
나가지 않았다(면제 동작 증거). **8개 프로파일 전부 재현율이 한 칸도 떨어지지 않았다.**

**#27 이 무엇을 바꿨나.** 링크·명세·트래픽 어디에도 안 걸리는 unlinked 공격면(백업·.git·설정·
로그 디렉터리·관리 화면)을 wordlist 프로브로 찾는다. Juice Shop 실측 기준 /support/logs·
/encryptionkeys 는 디렉터리 목록이 그대로 열려 있는데도 링크가 없어 지금까지의 정찰로는 도달하지
못했다. **기본 비활성(옵트인)** — 능동 탐색은 파괴성·소음·법적 경계가 있어 안전장치가 전제다.

측정: discover 프로파일이 static 대비 **R 42.1% → 55.3%, P 36.4% → 42.0%, F1 39.0% → 47.7%**.
셋 다 올랐다. wordlist 154항목 중 발견 7건(신규 unlinked 4건), soft-404 로 143건을 걸러냈다.

- **soft-404 캘리브레이션을 #26 과 공유한다.** internal/recon/probe 로 분리해 liveness·discover 가
  같은 판정을 쓴다. 똑같은 것을 두 번 만들면 두 곳이 어긋난다.
- **등급이 6단계가 됐다**: spec > traffic > headless-xhr > discover > crawl-link > static-regex.
  discover 는 등록 전에 실재를 확인하므로 라이브니스 재프로브 대상이 아니다(NeedsProbe=false).
- **wordlist 는 자체 작성**(154항목/2.7KB). 외부 인용이 없어 라이선스 제약이 없다.

> **#27 에서 배운 것 — 두 기능의 리스크 방향이 반대다.**
> 라이브니스(#26)는 우연히 터진 실 엔드포인트를 강등하면 재현율 손실이라 5xx 를 살린다.
> 능동 발견(#27)은 프레임워크 오류 페이지를 등록하면 오탐이라 5xx 를 버린다. Juice Shop 이
> 없는 API 경로에 500 "Unexpected path" 를 주는데, 실측에서 /api·/api/v1·/rest 4건이 이렇게
> 오탐으로 잡혔다가 걸러졌다. 공용 판정(probe.Exists)은 #26 편(5xx=실재)을 유지하고,
> discover 쪽에만 5xx 게이트를 뒀다 — 공용 함수를 한쪽 편의로 바꾸면 다른 쪽이 깨진다.
>
> **옵트인은 테스트로 못 박아야 한다.** 안 켜면 프로브 0건, 켜면 나감을 양방향으로 확인한다.
> 이 보장이 깨지면 사용자가 켜지도 않은 능동 탐색이 대상 서버로 나간다 — 법적 경계 문제다.

> **#26 에서 배운 것 — "2xx 를 받았다"와 "실재한다"는 다르다.**
> SPA 는 없는 경로에도 200 을 주므로, 크롤러가 스스로 만들어낸 요청(링크 추종·정규식 추출)은
> 응답을 받았다는 사실만으로 실재의 증거가 되지 않는다. 존재할 리 없는 경로로 baseline 을 잡고
> 본문 모양을 비교해야 갈린다. 반대로 정직하게 404 를 주는 서버(DVWA)는 baseline 자체가 불필요하다
> — 두 경로 모두 실측으로 확인했다.
>
> **함정 1 — 루트 경로 강등.** SPA 셸 HTML 은 곧 "/" 의 진짜 내용이라 baseline 과 같은 모양으로
> 보인다. 예외 처리하지 않으면 크롤 시작점이 통째로 사라진다(기존 크롤러 테스트가 Targets=[] 로 잡아냈다).
>
> **함정 2 — 401/403.** 인증 벽 뒤 엔드포인트를 죽은 것으로 강등하면 재현율이 무너진다.
> 5xx·3xx 도 부재의 증거가 아니다.
>
> **함정 3 — 등급 승계.** #25 의 mergeNode 는 "출처가 비어 있으면 채운다"였는데, 등급이 5단계가
> 되면 static-regex 노드에 traffic 노드가 병합될 때 낮은 등급이 남는다. 높은 등급이 이기도록 고쳤다.

> **#25 에서 겪은 함정 — SPA catch-all.**
> Juice Shop 은 **없는 경로에도 200 + `index.html`** 을 돌려준다. 상태코드로 명세 존재를 판정하면
> `/openapi.json`·`/swagger.json`·`/v3/api-docs`·`/graphql` 4개를 "발견"하고 HTML 을 파싱하려 든다.
> → content-type + 본문 필수 키까지 확인하고, 걸러낸 후보를 `Report.Rejected` 에 남겨 검증이
> 동작했음을 드러낸다(실측: 후보 20건 중 13건 거부, 명세 0건 생성).
>
> **부수 함정 — 예산 혼입.** 인제스트 요청 수를 크롤의 `res.Pages` 에 더했더니 프로브 18건이
> `MaxPages=10` 을 즉시 소진해 크롤이 첫 페이지에서 멈췄다. 기존 크롤러 테스트 2건이 깨져서 드러났다.
> `MaxPages` 는 크롤을 제한하는 예산이지 명세 프로브를 제한하는 값이 아니다.

> **#24 에서 겪은 실패 — §6에 추가할 값어치가 있다.**
> 형제 클러스터링의 첫 구현이 후보 조건을 "리프 + 파라미터 없음 + 고유비율 높음"으로만 잡았더니,
> juice-shop `/api` 밑의 REST 리소스 12종(`Products`·`Feedbacks`·`Challenges`…)이
> **전부 `/api/{slug}` 하나로 뭉개져** 재현율이 41.9% → 22.6% 로 무너졌다.
> 단위 테스트는 전부 통과했고, **하네스 실측에서만 드러났다.**
> → 교훈: 휴리스틱의 임계치는 합성 테스트로 검증되지 않는다. #22 같은 계기판이 없었으면
> 이 회귀는 조용히 머지됐을 것이다. 가드(`looksLikeValue`)를 넣고 실제 리소스명으로 회귀 테스트를 고정했다.

### #24 에서 넘긴 것

- `docs/recon-groundtruth/README.md` 의 "단계별 목표"에 있던 **`#3(정규화) 후 P ≥ 40%` 는 미달**로 기록했다.
  juice-shop 의 오탐은 값만 다른 중복 노드가 아니라 **SPA 클라이언트 라우트·정적자산·외부 링크**라,
  정규화가 아니라 **필터의 몫**임이 실측으로 확인됐다 → 라이브니스/필터(#5 계열)로 이월.
- (#25·#26 로 갱신) VAmPI 정답셋은 13 → 14(`GET /me`), Juice Shop 은 31 → 32(`GET /ftp`) → 34(`/api/Quantitys`·`/api/Recycles`) 가 됐다.
  둘 다 인제스터가 찾아냈으나 정답셋에 없어 오탐으로 계상되던 항목이고, 실재를 확인해 반영했다.
- DVWA·VAmPI 도 회귀 확인차 재측정했다(#24 완료기준 밖). **전·후 8행이 한 칸도 다르지 않았다.**
  DVWA 는 경로가 전부 고정 PHP 파일이라 접을 가변 세그먼트가 없고(팽창률 1.02x/1.01x 유지),
  VAmPI 는 링크 없는 API 라 크롤이 static 0건·headless 2건뿐이라 팽창률 측정 자체가 성립하지 않는다.
  → **정규화 v2 가 실제로 이득을 보는 대상은 Juice Shop 뿐**이다.
  (이번 DVWA 는 `ghcr.io/digininja/dvwa` + `mariadb:10` 구성이라 기존 baseline 의
  `vulnerables/web-dvwa` 수치와 절대값을 나란히 읽으면 안 된다.)

---

## 0. 이 프로젝트가 무엇인가 (3문단 요약)

**AVA**(Go 모듈명은 `proxypoc`, `backend/go.mod:1`)는 LLM을 판단 엔진으로 쓰는 **반자동 웹 취약점 진단 도구**다.
국내 규제 대응이 핵심 가치로, 「주요정보통신기반시설 기술적 취약점 분석·평가 상세가이드」와
「전자금융기반시설 보안 취약점 평가기준 안내서」의 점검항목표에 진단 결과를 자동 매핑한다.
자세한 제품 명세는 `docs/spec.md`(394줄), 설계 배경은 `docs/00-아키텍처.md`(282줄)에 있다.

구조는 **Go 단일 정적 바이너리 + React SPA**다. 프론트 빌드 산출물을 `//go:embed`로 바이너리에 넣어
폐쇄망에 단일 실행파일로 배포하는 것을 노린다. 한 프로세스가 리스너 3개를 띄운다 —
MITM 프록시 `:8080`, MCP 서버 `:8765`, 웹 GUI `:8090` (`backend/cmd/proxy/main.go:159,163,172`).

코드는 백엔드가 압도적으로 크다. 비테스트 Go 11,256줄 + 테스트 3,280줄, 프론트 `src/` 3,054줄.

```bash
find backend -name '*.go' ! -name '*_test.go' | xargs wc -l | tail -1   # 11256
find backend -name '*_test.go'                | xargs wc -l | tail -1   # 3280
git ls-files frontend/src                     | xargs wc -l | tail -1   # 3054
```

---

## 1. 이 브랜치가 한 것 / 하지 않은 것

### 1.1 배경 — 인수 시점의 레포는 빌드가 불가능했다

서로 맞물린 두 단절이 있었다.

**단절 1 — 백엔드 컴파일 실패.** `backend/internal/webui/webui.go:46`의 `//go:embed all:dist`가
가리키는 `backend/internal/webui/dist/`가 존재하지 않았다.

```
internal/webui/webui.go:46:12: pattern all:dist: no matching files found
```

이 에러 하나가 `internal/webui`와, 이를 import하는 제품 본체 `cmd/proxy`
(`backend/cmd/proxy/main.go:35`)를 함께 무너뜨렸다.

**단절 2 — 프론트엔드 소스 부재.** `frontend/index.html:10`이 로드하는 `/src/main.tsx`가 없었고,
레포 전체에 `.tsx`/`.jsx`/`vite.config.*`/`tsconfig.json`이 0개였다.
`dist/`는 프론트 빌드 산출물인데 그 프론트를 빌드할 소스가 없어, 어느 쪽부터도 풀리지 않았다.

### 1.2 한 것

| 카테고리 | 내용 | 규모 |
|---|---|---|
| 프론트엔드 소스 | `frontend/src/` 19개 신규 — 화면 11개 + `Login`·`App`·`main.tsx`·공용 컴포넌트 3개 + `theme.ts`·`index.css` | +2,755 |
| 빌드 설정 | `frontend/vite.config.ts`, `frontend/tsconfig.json` | +37 |
| 문서 | `docs/CODEBASE.md` 신규(코드베이스 감사), `README.md` 빌드 순서 명시 | +711 / −1 |
| `.gitignore` | 신규 — 시크릿·상태 JSON·빌드 산출물 차단 | +105 |

`vite.config.ts`의 `build.outDir`이 `../backend/internal/webui/dist`를 가리키면서 두 단절이 함께 해소됐다.
빌드를 임시로 통과시키려 넣었던 플레이스홀더(`dist/index.html`)는 이 브랜치 안에서
추가(`549af8f`)됐다가 제거(`6f84178`)되어, 누적 diff에는 남지 않는다.

부수 효과로 `frontend/src/api.ts`가 데드코드에서 실사용 코드가 됐다 —
12개 파일이 import하며 `usePoll` 51회, `apiPost` 22회, `apiGet` 2회 호출한다.

```bash
grep -rl "from '\.\./api'\|from '\./api'" frontend/src/ | wc -l   # 12
```

### 1.3 하지 않은 것 — **백엔드 `.go` 파일을 한 번도 건드리지 않았다**

> **⚠ 이 절은 그 브랜치의 diff에 한해서만 참이다.** 현재 레포에는 해당하지 않는다 —
> 이후 이슈 #6·#22·#23·#31·#24 가 백엔드를 바꿨다. §0 갱신 블록 참조.

```bash
git diff --name-status c3ea722..HEAD -- backend/   # 출력 없음 = 순변경 0건
```

`backend/` 경로가 등장하는 유일한 파일은 위의 플레이스홀더뿐이고, 추가·삭제가 상쇄된다.
따라서 **백엔드 동작은 인수 시점과 완전히 동일하다.** §4의 미해결 항목은 전부 그대로 살아 있다.

---

## 2. 빌드 / 실행 — 순서 의존이 있다

### 2.1 핵심 제약

`backend/internal/webui/dist/`는 **`npm run build` 산출물이며 git에 커밋되지 않는다**
(`.gitignore`에서 무시). 반면 `//go:embed all:dist`는 그 디렉터리가
**컴파일 시점에 비어 있지 않을 것**을 요구한다.

> **clone 직후 `go build`부터 실행하면 반드시 실패한다.** 이것이 이 프로젝트에서
> 가장 자주 밟게 될 함정이다. 에러 메시지가 embed를 가리키므로 원인은 명확하지만,
> "왜 소스만 받았는데 컴파일이 안 되지" 하고 헤매기 쉽다.

참고로 `go list ./...`, `go vet`, `gopls` 등 **패키지 로딩을 하는 모든 도구가 같은 이유로 실패한다.**
IDE가 프로젝트를 못 읽는다면 십중팔구 프론트를 아직 빌드하지 않은 것이다.

### 2.2 재현 명령 (전문)

```bash
git clone --branch claude/repo-codebase-audit-qy91vo https://github.com/Vornsk/AVA.git /tmp/verify
cd /tmp/verify

# ── [순서 검증] 프론트 빌드 없이 go build → 실패하는 것이 정상 ──
cd backend && go build ./...
#   internal/webui/webui.go:46:12: pattern all:dist: no matching files found
#   [종료코드 1]

# ── 1) 프론트 의존성 ──
cd ../frontend && npm ci

# ── 2) 프론트 빌드 (→ ../backend/internal/webui/dist) ──
npm run build

# ── 3) 타입체크 — "build" 스크립트가 tsc 를 호출하지 않으므로 별도 실행 ──
npx tsc --noEmit

# ── 4~6) 백엔드 ──
cd ../backend
go build ./...
go vet ./...
go test ./...

# ── 7) 빌드 산출물이 git status 를 오염시키지 않는지 ──
cd .. && git status --short --untracked-files=all
```

### 2.3 실측 결과 (fresh clone 기준)

| # | 단계 | 결과 |
|---|---|---|
| 0 | 순서 검증 (`npm run build` 생략) | 예상대로 embed 에러, 종료코드 1 |
| 1 | `npm ci` | ✅ 0 — 85 패키지, 취약점 0건 |
| 2 | `npm run build` | ✅ 0 — 1,811 모듈 → `index.html` 0.43 kB / CSS 20.67 kB / JS 270.28 kB (gzip 75.49 kB) |
| 3 | `npx tsc --noEmit` | ✅ 0 — **에러 0건** (`strict`, `noUnusedLocals`, `noUnusedParameters` 활성) |
| 4 | `go build ./...` | ✅ 0 — 출력 없음 |
| 5 | `go vet ./...` | ✅ 0 — 출력 없음 |
| 6 | `go test ./...` | ✅ 0 — **ok 21 / FAIL 0** (총 35 패키지, 14개는 `_test.go` 없음) |
| 7 | 빌드 후 `git status` | ✅ 비어 있음 |

### 2.4 실행

```bash
cd backend
go build -o proxy ./cmd/proxy
./proxy                      # 최초 실행 시 ca.crt / ca.key 생성
```

웹 GUI `http://127.0.0.1:8090` — 데모 계정 `leader / leader123`, `analyst / analyst123`
(`README.md:74`, 시드는 `backend/internal/user/user.go:125`).

개발 중에는 `cd frontend && npm run dev`(Vite `:5173`)를 쓸 수 있다.
`vite.config.ts`의 `server.proxy`가 `/api`를 `http://127.0.0.1:8090`으로 넘긴다.

---

## 3. 다음 작업 순서

**이 순서에는 이유가 있다. ④를 먼저 하면 고친 것을 증명할 수 없다.**

### ① `docs/CODEBASE.md`·`README.md` 사실 오류 6건 정리 → PR #2 머지

`docs/CODEBASE.md`는 **UI 도입 이전 시점의 스냅샷 감사**다. §0에 갱신 블록으로 면책해 두었으나
범위를 §3.4·§4.1·§5로만 적어 아래가 빠졌고, 일부 제목은 본문과 정면으로 모순된다.

| # | 위치 | 문제 |
|---|---|---|
| 1 | `README.md:61` vs `:73` | `cd frontend`와 `cd proxy-poc/backend`의 경로 표기가 같은 절에서 어긋남. 앞쪽만 고치고 뒤를 놔둔 결과 |
| 2 | `docs/CODEBASE.md:10` | §0 제목이 "이 레포는 현재 빌드되지 않는다" — 바로 아래 갱신 블록과 모순 |
| 3 | `docs/CODEBASE.md:135` | §1.4 제목 "`frontend/` — 파일 4개가 전부" (현재 25개) |
| 4 | `docs/CODEBASE.md:335` | §4.1 제목 "도달 가능한 화면 0개" (현재 11개) |
| 5 | `docs/CODEBASE.md:178` | §2.2 "실제 소스 import는 단 한 줄이다" (현재 lucide 15 + react 14 + react-dom 1 = 30줄) |
| 6 | `docs/CODEBASE.md:590,591,599` | §7 이슈 표의 1·2·10번(빌드 불가 / 프론트 부재 / `.gitignore` 부재)이 이미 해결됐는데 미해결로 등재 |
| 7 | `docs/CODEBASE.md:92,420,422,466` | ~~MCP 툴 개수가 "56"으로 적혀 있으나 실측 54~~ **(해소).** 작성 당시 실측 54였으나, **이슈 #5로 `proxy_status`·`set_capture` 2개가 추가되어 현재 실측 56** — CODEBASE의 "56"과 일치한다. `grep -c 'mcp.AddTool' backend/internal/mcpserver/mcpserver.go` → 56 |

**왜 먼저인가.** 이 문서가 후속 작업의 유일한 지도다. 지도에 사실과 반대인 문장이 있으면
뒤따르는 모든 판단이 오염된다. 수정량이 작고(제목 문구 수준) 위험이 0이라 머지를 막을 이유가 없다.

`README.md:4`의 "**React 웹 GUI**를 얹은"은 이제 사실이므로 **수정 대상이 아니다.**

### ② CI 배선

**갱신:** `.github/`는 이제 존재한다 — 이슈·PR 템플릿(`ISSUE_TEMPLATE/` 3종 + `PULL_REQUEST_TEMPLATE.md` + `config.yml`).
다만 **CI 워크플로(`.github/workflows/`)는 아직 없다** → 빌드·테스트를 강제하는 자동화는 여전히 부재.

```bash
ls .github/workflows 2>/dev/null || echo "워크플로 없음"
```

즉 §2의 `npm run build` → `go build` 순서가 **README 산문으로만 보장된다.**
사람이 문서를 읽지 않으면 그대로 깨지고, 기계는 아무도 막아주지 않는다.

최소 워크플로는 §2.2의 1→6단계를 그대로 옮기면 된다. `npm ci`가 `package-lock.json`을 요구하는데
이미 커밋되어 있다(`frontend/package-lock.json`, lockfileVersion 3).

**왜 ②인가.** ③의 베이스라인 재측정과 ④의 보안 수정 모두 "고치기 전/후"를 기계적으로 비교해야 한다.
CI가 없으면 그 비교가 사람의 로컬 실행에 의존하고, 이 프로젝트는 이미 그 방식으로
수치가 갈린 전례가 있다(§6.1).

### ③ 베이스라인 재측정

> **⚠ 아래 표의 수치는 2026-08-10 기준이라 전부 낡았다.** 재측정값은 §0 갱신 블록의
> "재측정 베이스라인" 표를 볼 것. **다만 "기준선을 CI에 고정한다"는 과제 자체는 그대로 미해결이다**
> (§3 ② CI 워크플로가 아직 없다).

**"26개 패키지" vs "ok 21" 불일치 — 규명 완료. 새로 조사할 것은 없다.**

결론부터: **26은 처음부터 틀린 수치였다.** 실제로 테스트를 가진 패키지는 감사 시점에도 지금도 21개다.

```bash
# 감사 시점 커밋 기준
git ls-tree -r --name-only c3ea722 | grep '_test\.go$' | xargs -n1 dirname | sort -u | wc -l   # 21
# 현재 HEAD 기준
git ls-files | grep '_test\.go$' | xargs -n1 dirname | sort -u | wc -l                          # 21
```

경위는 이렇다. 코드베이스 감사에 투입한 서브에이전트가 "26/26 test packages green"으로 보고했고,
그것이 검증 없이 `docs/CODEBASE.md`에 실렸다. 정작 같은 문서 §1.2의 패키지별 테스트 LOC 표에는
21개만 올라 있어 **문서가 자기 자신과 모순된 상태**였다. 이후 실측으로 정정했다(커밋 `5c1d95d`).

따라서 ③의 실제 과제는 "불일치 규명"이 아니라 **믿을 수 있는 베이스라인을 CI에 고정하는 것**이다.
고정할 수치:

| 항목 | 값 | 재현 명령 |
|---|---|---|
| 전체 Go 패키지 | 35 | `go list ./... \| wc -l` (프론트 빌드 후) |
| 테스트 보유 패키지 | 21 | `git ls-files \| grep '_test\.go$' \| xargs -n1 dirname \| sort -u \| wc -l` |
| 테스트 없는 패키지 | 14 | 위 둘의 차 |
| `go test` 통과 | ok 21 / FAIL 0 | `go test ./...` |
| 웹 라우트 등록 | **58** (57 `HandleFunc` + 1 `Handle`) | `grep -c 'mux.HandleFunc' backend/internal/webui/webui.go` 와 `grep -c 'mux.Handle(' ...` |
| MCP 툴 | **54** | `grep -c 'mcp.AddTool' backend/internal/mcpserver/mcpserver.go` |
| 프론트 타입 에러 | 0 | `cd frontend && npx tsc --noEmit` |

**왜 ③인가.** ④의 보안 수정은 "고쳐도 다른 게 안 깨졌다"를 보여야 하는데,
그 기준선 자체가 한 번 틀렸던 전적이 있다. 먼저 기준선을 못 박아야 한다.

### ④ 보안 3건 수정 — **③ 이후에**

> **⚠ 부분 갱신.** "이 패키지들에 테스트가 0개"는 `webui` 에는 더 이상 해당하지 않는다
> (`endpoints_test.go`·`projects_delete_test.go` 2개). `mcpserver`·`audit` 은 **여전히 0개**라
> 아래 논지(테스트 없이 인증·인가를 손대지 말 것)는 그 둘에 대해 그대로 유효하다.

대상은 §4 표의 1·2·3번이다.

**왜 지금 하면 안 되는가.** 세 건이 모두 `internal/webui`와 `internal/mcpserver`,
`internal/audit`에 있는데 **이 패키지들에 테스트가 0개다.**

```bash
ls backend/internal/webui/*_test.go backend/internal/mcpserver/*_test.go \
   backend/internal/audit/*_test.go 2>/dev/null || echo "테스트 파일 없음"
wc -l backend/internal/webui/webui.go backend/internal/mcpserver/mcpserver.go   # 1017 + 797 = 1814
```

`webui`(1,017줄)와 `mcpserver`(797줄)는 합계 1,814줄로 **코드의 약 12.5%이자 외부 공격면의 100%**다.
여기에 인증·인가를 손대면서 회귀 테스트가 없으면, 고쳤다는 주장도 안 깨졌다는 주장도 증명할 수 없다.

**권장 순서:** 각 건마다 (a) 현재의 잘못된 동작을 고정하는 실패 테스트를 먼저 쓰고 →
(b) 수정하고 → (c) 테스트가 통과하는지 본다. 특히 2번(bundle ACL)은
형제 라우트(`webui.go:121-145`의 `requireAccess` 패턴)가 이미 올바른 형태를 보여주므로 참고하기 쉽다.

---

## 4. 미해결 항목

전부 **백엔드 로직 변경이 필요해 이 브랜치에서 손대지 않았다.** 인수 시점 그대로다.

| # | 항목 | 위치 | 내용과 영향 |
|---|---|---|---|
| 1 | **MCP 표면 무인증 + 전역 리더 권한** | `backend/internal/mcpserver/mcpserver.go:717-719`, `:758-759` | `:717-719`가 `withAuth` 같은 미들웨어 없이 `mcp.NewStreamableHTTPHandler`를 그대로 `http.ListenAndServe`에 바인딩한다. `authz()`(`:758-759`)는 프로세스 전역 `user.Current()`로 신원을 해석하는데 `user.Seed()`(`backend/internal/user/user.go:125`)가 이를 `leader`로 초기화한다. → **`:8765`에 도달 가능한 클라이언트는 누구나 리더 권한**으로 `run_scan`·`set_project_credentials`·`export_project`·`create_project`를 호출한다. 기본 바인딩 `127.0.0.1`만이 방어다. 추가로 `export_project`/`import_project`가 툴 인자의 파일시스템 경로를 검증 없이 사용한다(`:307` `os.WriteFile`, `:321` `os.ReadFile`). |
| 2 | **`GET /api/projects/{id}/bundle` ACL 누락** | `backend/internal/webui/webui.go:622-631` (2026-08-18 재확인, 미해결) | `bundleDownload`가 형제 `/api/projects/{id}/*` 라우트와 달리 `authorize`도 `requireAccess`도 호출하지 않고 곧바로 `bundle.Export(r.PathValue("id"))`를 부른다. `withAuth`의 세션 검사만 걸리므로 **인증된 아무 분석가나 임의 프로젝트를 통째로 내보낼 수 있다.** |
| 3 | **`audit.json` 쓰기 전용 — 재시작마다 감사 추적 파괴** | `backend/internal/audit/audit.go` | `Record()`가 `audit.json`을 쓰지만(`:44`) **패키지에 `Load()`가 없다.** 노출 함수는 `Record`(`:31`)·`List`(`:48`)·`Reset`(`:55`) 셋뿐. 인메모리 슬라이스가 nil로 시작하므로 **재시작 후 첫 `Record()`가 파일을 1건짜리 배열로 덮어쓴다.** `webui.go:921`이 이 파일을 "규제 제출용 증적"으로 문서화하고 있어 실질적 결함이다. `internal/profile`도 동일 형태(`profile.go:32`에 `Save()`만 있고 `Load()` 없음). |
| 4 | **영속화 경로가 전부 상대경로** | `backend/internal/finding/finding.go:16`, `backend/internal/scanengine/scanengine.go:285`, `backend/internal/profile/profile.go:32` 외 | `const file = "findings.json"` 식의 맨 상대 경로라 **상태가 프로세스를 시작한 디렉터리에 종속된다.** 다른 디렉터리에서 실행하면 조용히 빈 상태로 시작하고, 경고도 없다. `go test`가 각 패키지 디렉터리에 `findings.json`·`endpoints.json`·`scanruns.json`·`profiles.json`을 흩뿌리는 것도 같은 원인이다(`.gitignore`의 `backend/internal/**/*.json` 규칙이 이를 막는다). |

검증:

```bash
grep -n '^func' backend/internal/audit/audit.go          # Record / List / Reset — Load 없음
grep -c 'func Load' backend/internal/audit/audit.go      # 0
sed -n '598,607p' backend/internal/webui/webui.go        # authorize / requireAccess 호출 없음
sed -n '755,760p' backend/internal/mcpserver/mcpserver.go
```

그 밖에 `docs/CODEBASE.md` §7에 정리된 항목 — HTTP 에러 응답 형식 불일치(평문 `http.Error` vs
유일한 JSON 바디 `webui.go:653-655`), `docs/*.yaml` 4개의 스키마 비호환 고아화 — 도 그대로다.

---

## 5. 환경 제약

### 5.1 `gh` CLI가 없다 → GitHub API를 쓴다

```bash
which gh || echo "gh 없음"
```

이 실행 환경에는 `gh`도 `hub`도 설치돼 있지 않다. PR 생성·이슈 조작·리뷰 코멘트는
**GitHub API(또는 이를 감싼 MCP 도구)로 처리해야 한다.**
실제로 PR #2와 이슈 #1도 API로 생성했다. `gh pr create`를 그대로 실행하면 실패한다.

### 5.2 그 외

- **Go 1.26.5** — `go.mod:3`이 패치 버전까지 고정한다(`go 1.26.5`). 흔치 않은 형태이므로
  툴체인 버전이 다르면 먼저 이것을 확인할 것.
- **Node 22 / npm 10** 로 검증했다. `package.json`에 `engines` 필드는 없다.
- `frontend/node_modules`는 커밋되지 않는다. `npm ci`로 설치한다.

---

## 6. 이 프로젝트에서 관찰된 실패 모드

**실제로 겪은 것만 적는다.** 같은 함정을 다시 밟지 않도록.

### 6.1 서브에이전트 보고 수치가 서로 갈렸다

코드베이스 감사에 서브에이전트 3개를 병렬로 투입했는데, **같은 파일의 라우트 수를 각각 51 / 57 / 59로 보고했다.**
직접 세어 보니 **58**이었다(57 `mux.HandleFunc` + 1 `mux.Handle("/")`).

```bash
grep -c 'mux.HandleFunc' backend/internal/webui/webui.go   # 57
grep -c 'mux.Handle('    backend/internal/webui/webui.go   # 1
```

같은 사건의 다른 사례가 §3③의 "26개 패키지"다. 서브에이전트가 "26/26 green"으로 보고했고
검증 없이 문서에 실렸으나, 실제 값은 21이었다.

**세 번째 사례는 이 문서를 쓰는 도중에 나왔다.** MCP 툴 개수를 서브에이전트 보고대로 "56"이라
적었다가, 근거 검증 단계에서 실측하니 **54**였다. `docs/CODEBASE.md`에도 같은 값이 4곳
(`:92`, `:420`, `:422`, `:466`) 퍼져 있다 — §3①의 7번 항목.

```bash
grep -c 'mcp.AddTool' backend/internal/mcpserver/mcpserver.go   # 54
```

즉 이 실패 모드는 한 번 발생하고 끝난 것이 아니라 **세 번 반복됐고, 세 번 모두 서브에이전트의
개수 보고였다.** 같은 작업에서 인용한 `파일:줄` 근거 중 3건(`user.go:122` → 실제 `:125`,
`checklist.go:45` → 실제 `:46`, MCP 툴 56 → 54)이 검증 단계에서 걸러졌다.

또 한 건: 한 에이전트가 "파괴적 라우트가 GET으로 도달 가능"하다고 보고했으나 사실이 아니었다.
`POST /api/findings/clear`(`webui.go:174`)는 mux 패턴에 메서드 접두사가 있어
Go 1.22+ `ServeMux`가 메서드를 강제한다. 핸들러 본문만 보고 등록부를 확인하지 않은 오판이었다.

> **교훈:** 서브에이전트 보고의 **핵심 수치는 반드시 직접 재확인한다.**
> 특히 개수·통과/실패·보안 판정은 그대로 옮기지 말 것.
> 여러 에이전트의 답이 갈리면 그 자체가 신호이니, 다수결이 아니라 실측으로 결정한다.

### 6.2 VulnDef 33과 CheckItem 88을 혼동했다

`backend/internal/checklist/seed.go`에는 `ID:` 필드가 **121개** 있는데, 이는 두 종류가 섞인 수다.
한 서브에이전트가 이를 "점검항목 121개 중 19개만 자동화"로 보고했으나 틀렸다.

```bash
grep -c 'ID:' backend/internal/checklist/seed.go                      # 121  ← 섞인 합계
sed -n '15,87p'  backend/internal/checklist/seed.go | grep -c 'ID:'   # 33   ← VulnDef (2층)
sed -n '88,$p'   backend/internal/checklist/seed.go | grep -c 'ID:'   # 88   ← CheckItem (3층)
grep -c 'Detectors:' backend/internal/checklist/seed.go               # 19   ← VulnDef 에만 달림
```

정확한 그림은 이렇다. **VulnDef 33개 중 19개가 detector 매핑을 가지므로 14개는 수동 점검**이고,
**CheckItem은 88개**(전자금융 66 / 주요정보통신기반시설 21 / 모바일 1)다.
`Detectors` 필드는 `CheckItem`이 아니라 `VulnDef`에 달린다(`checklist.go:36`).

```bash
sed -n '88,$p' backend/internal/checklist/seed.go | grep -o 'Scheme: *[A-Za-z]*' | sort | uniq -c
```

> **교훈:** 이 코드베이스의 점검항목은 **3계층**이다 —
> Detector(1층, 코드) → VulnDef(2층, 취약점 정의) → CheckItem(3층, 스킴별 규제항목).
> 층을 섞어 세면 규제 커버리지 수치가 통째로 틀어진다. 자세한 구조는 `docs/spec.md` §6.

### 6.3 `git -C`가 엉뚱한 경로에 worktree를 만들었다

`git -C /home/user/AVA worktree add uicheck <ref>`를 임시 디렉터리에서 실행했는데,
**worktree가 `-C` 기준 경로인 `/home/user/AVA/uicheck`에 생성됐다.**
의도는 임시 디렉터리 안에 만드는 것이었다. 결과적으로 레포 워킹트리가 오염됐고
`git status`에 `?? uicheck/`가 떴다. `git worktree remove --force uicheck`로 정리했다.

```bash
git worktree list   # 예상 밖의 worktree 가 있는지 확인
```

> **교훈:** `git -C`는 **모든 상대 경로 인자의 기준까지 바꾼다.** 편의를 위해 쓰다가
> 산출물 위치를 놓치기 쉽다. **작업 디렉터리를 실제로 이동한 뒤 실행하는 편이 안전하다.**
> 임시 검증은 레포 밖(예: `/tmp`)에 `git clone`하는 쪽이 부작용이 없다.

### 6.4 (부수) `git check-ignore`의 종료 코드와 출력을 혼동했다

`.gitignore` 검증 중 `git check-ignore -v <path>`가 출력을 내길래 "무시됨"으로 판정했으나 오판이었다.
출력된 것은 **부정 규칙**(`!`로 시작)이었고, `-v`는 매치된 패턴을 종류와 무관하게 보여준다.

```bash
git check-ignore -q <path>; echo $?     # 0 = 무시됨, 1 = 무시 안 됨  ← 이쪽이 판정 기준
git add --dry-run <path>                # 가장 확실한 검증
```

> **교훈:** 무시 여부는 **출력 유무가 아니라 종료 코드**로 판정한다.

---

## 7. 빠른 참조

| 알고 싶은 것 | 문서 |
|---|---|
| 제품 요구사항·FR 번호 체계 | `docs/spec.md` (394줄) |
| 설계 배경·goproxy 선택 이유·겪은 함정 | `docs/00-아키텍처.md` (282줄) |
| 화면별 명세 11개 | `docs/01-개요.md` ~ `docs/11-사용자.md` |
| **코드베이스 구조·패턴·데이터 흐름 감사** | `docs/CODEBASE.md` — **§0 갱신 블록의 면책 범위를 먼저 읽을 것** |
| 문서 사이트 재생성 | `node docs/build.mjs` → `docs/index.html` (직접 편집 금지) |

**주의:** `docs/*.yaml` 4개(`vulndefs.yaml`, `checkitems.{kii,fin,mobile}.yaml`)는
**런타임이 소비하지 않는 고아 산출물이다.** 백엔드는 CWD의 `checklist.config.yaml`을 읽고
(`backend/cmd/proxy/main.go:75`), 없으면 `backend/internal/checklist/seed.go`의 하드코딩 데이터로 생성한다.
게다가 스키마가 비호환이라 경로를 맞춰줘도 파싱에 실패한다 —
Go의 `CheckItem.Vuln`은 스칼라 `string`인데(`checklist.go:46`) YAML은 리스트다(`checkitems.kii.yaml:6-12`).
점검항목을 바꾸려면 `seed.go`를 고쳐야 한다. 자세한 근거는 `docs/CODEBASE.md` §5.4.
