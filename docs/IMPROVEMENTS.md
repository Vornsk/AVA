# IMPROVEMENTS — 전체 브랜치 스캔 및 개선 방향

> 스캔 시점 **2026-09-09** · 기준 `origin/main` = `d0c7f00` (2026-08-27) · 총 196 커밋
>
> 모든 수치는 `main` 을 임시 디렉터리에 **fresh clone 해서 실측**했다. 재현 명령을 함께 적었다.
> 실행으로 확인하지 않은 판단은 **추정**으로 표시했다.
> 이 문서는 진단과 방향 제시만 한다 — 코드는 건드리지 않았다.

---

## 1. 브랜치 스캔

```bash
git fetch origin --prune
git for-each-ref --sort=-committerdate refs/remotes/origin \
  --format='%(committerdate:short) %(refname:short) %(contents:subject)'
```

| 브랜치 | 최종 커밋 | main 대비 | 상태 |
|---|---|---|---|
| `main` | 2026-08-27 `d0c7f00` | — | 기준 |
| `seona` | 2026-08-27 `12f7154` | 0 ahead / 6 behind | ✅ 병합됨 (실질 개발 브랜치) |
| `claude/repo-handoff-assessment-lgjz2i` | 2026-08-10 `278eb49` | **1 ahead / 183 behind** | ⚠️ **미병합·방치** |
| `claude/repo-codebase-audit-qy91vo` | 2026-08-10 `0ef8b19` | 0 ahead / 183 behind | ✅ 병합됨 (PR #2) |

```bash
for b in main seona claude/repo-handoff-assessment-lgjz2i claude/repo-codebase-audit-qy91vo; do
  echo "$b ahead:$(git rev-list --count origin/main..origin/$b) behind:$(git rev-list --count origin/$b..origin/main)"
done
```

**개발은 `seona` → `main` 단일 흐름으로 건강하게 돌아간다.** 미병합 PR은 0건이다.

**다만 `claude/repo-handoff-assessment-lgjz2i` 하나가 183커밋 뒤처진 채 방치돼 있다.**
이 브랜치는 `docs/CODEBASE.md`·`README.md`·`docs/index.html` 의 사실 오류 7건을 고친 것인데,
그 수정이 `main` 에 반영되지 않아 **오류가 그대로 살아 있다.** 대표 증거:

```bash
git show 278eb49:docs/CODEBASE.md | sed -n '10p'
#   ## 0. 한 줄 요약 — 빌드 불가였던 두 단절 (현재 해소됨 — 아래 갱신 블록 참조)
git show origin/main:docs/CODEBASE.md | sed -n '10p'
#   ## 0. 한 줄 요약 — 이 레포는 현재 빌드되지 않는다        ← 사실과 반대
```

지금 `main` 은 정상 빌드된다(§2). 이 브랜치는 183커밋 뒤처져 그대로 머지하기 어려우므로,
**브랜치를 되살리기보다 §5-C 의 문서 재생성 작업에 흡수시키고 삭제하는 편이 낫다.**

---

## 2. 현재 상태 — 실측 베이스라인

fresh clone 후 전 파이프라인을 순서대로 실행했다. **전부 통과한다.**

```bash
git clone --branch main https://github.com/Vornsk/AVA.git /tmp/scan && cd /tmp/scan
cd frontend && npm ci && npm run build && npx tsc --noEmit
cd ../backend && go build ./... && go vet ./... && go test ./...
```

| 단계 | 결과 |
|---|---|
| `npm ci` | ✅ exit 0 — 취약점 0건 |
| `npm run build` | ✅ exit 0 — 1,816 모듈 → `index.html` 0.50 kB / CSS 25.39 kB / **JS 386.18 kB (gzip 103.74 kB)** |
| `npx tsc --noEmit` | ✅ exit 0 — 에러 0건 |
| `go build ./...` | ✅ exit 0 |
| `go vet ./...` | ✅ exit 0 |
| `go test ./...` | ✅ exit 0 — **ok 34 / FAIL 0 / no test 14** |

### 규모 변화 (2026-08-10 인수 시점 → 현재)

| 항목 | 8/10 | **현재** | 재현 명령 |
|---|---|---|---|
| 백엔드 비테스트 LOC | 11,256 | **18,763** | `find backend -name '*.go' ! -name '*_test.go' \| xargs wc -l \| tail -1` |
| 백엔드 테스트 LOC | 3,280 | **9,642** | `find backend -name '*_test.go' \| xargs wc -l \| tail -1` |
| 프론트 `src/` LOC | 3,054 | **5,913** | `git ls-files frontend/src \| xargs wc -l \| tail -1` |
| Go 패키지 | 35 | **48** | `cd backend && go list ./... \| wc -l` |
| 테스트 보유 패키지 | 21 | **34** | `git ls-files \| grep '_test\.go$' \| xargs -n1 dirname \| sort -u \| wc -l` |
| 웹 라우트 등록 | 58 | **74** | `grep -ch 'mux.HandleFunc\|mux.Handle(' backend/internal/webui/*.go \| paste -sd+ \| bc` |
| MCP 툴 | 54 | **56** | `grep -c 'mcp.AddTool' backend/internal/mcpserver/mcpserver.go` |

**테스트 LOC가 3배(3,280 → 9,642)로 늘었다.** 벤치 하네스(§4-1)까지 붙은 걸 보면
품질을 숫자로 관리하려는 방향이 자리 잡았다. 이 문서의 개선 제안은 그 흐름을 전제로 한다.

---

## 3. 개선 방향 — 우선순위

### A. 규제 도구 최소 자격 3건 — **최우선, 이미 이슈 #50으로 등록됨**

[이슈 #50](https://github.com/Vornsk/AVA/issues/50) 이 2026-08-21에 열렸고 **19일째 손대지 않았다.**
세 건 모두 오늘 재확인한 결과 **그대로 살아 있다.**

| # | 결함 | 현재 위치 (2026-09-09 실측) | 확인 명령 |
|---|---|---|---|
| 1 | `audit.json` 쓰기 전용 — 재시작마다 감사 추적 파괴 | `internal/audit/audit.go` — 노출 함수 `Record`(:31)·`List`(:48)·`Reset`(:55), **`Load` 없음** | `grep -c 'func Load' backend/internal/audit/audit.go` → `0` |
| 2 | `GET /api/projects/{id}/bundle` 인가 누락 | 등록 `webui.go:210` / 핸들러 **`webui.go:744-753`** — `authorize`·`requireAccess` 호출 없이 곧바로 `bundle.Export` | `sed -n '744,753p' backend/internal/webui/webui.go` |
| 3 | MCP 표면(:8765) 무인증 + 전역 리더 권한 | `mcpserver.go:751,753` 인증 미들웨어 없이 바인딩 / `authz()` `:792-793` 이 전역 `user.Current()` 사용 | `grep -n 'ListenAndServe\|func authz' backend/internal/mcpserver/mcpserver.go` |

**왜 최우선인가.** 이 제품의 정의는 "규제 대응 진단 도구"다. 감사 증적이 재시작마다 사라지고
프로젝트 격리가 뚫리는 상태에서는 **도구 자체가 규제 산출물의 신뢰 근거가 되지 못한다.**
기능을 아무리 더해도 이 셋이 남아 있으면 제품 정의가 성립하지 않는다.

**착수 전 정리할 것 하나.** 3번(MCP 인증)은 설계 결정이 필요하다. MCP 클라이언트는 브라우저가
아니라 외부 에이전트라 쿠키 세션이 맞지 않는다. 토큰 방식·mTLS·유닉스 소켓 중 무엇을 쓸지가
갈리고, 이건 **새 추상화 도입**이라 착수 전에 합의가 필요하다(CLAUDE.md 워크플로 규칙).
1번·2번은 그런 결정이 없고 국소 수정이라 먼저 처리할 수 있다.

> **선행 조건이 하나 있다.** 세 결함이 있는 `internal/audit`·`internal/mcpserver` 는 **테스트가 0개**다
> (§3-D). 인가 로직을 고치면서 회귀 테스트가 없으면 "고쳤다"도 "안 깨졌다"도 증명할 수 없다.
> 각 건마다 **현재의 잘못된 동작을 고정하는 실패 테스트를 먼저 쓰고** 고치는 순서를 권한다.
> `internal/webui` 는 이미 테스트가 8개 붙어 있어(§3-D) 2번은 그 패턴을 그대로 따르면 된다.

---

### B. CI 부재 — 구조적 위험, 이슈 없음

```bash
ls .github/workflows 2>/dev/null || echo "없음"
find .github -type f    # ISSUE_TEMPLATE 4종뿐
```

**`.github/workflows/` 가 없다.** 이 레포에는 두 개의 깨지기 쉬운 순서 의존이 있는데,
둘 다 사람이 문서를 읽는 것에만 의존한다.

1. **프론트 → 백엔드 빌드 순서.** `backend/internal/webui/dist` 는 `//go:embed` 대상이면서
   git에 커밋되지 않는다. `npm run build` 를 건너뛰면 `go build` 가 반드시 실패한다.
2. **타입체크.** `npm run build` 가 `tsc --noEmit && vite build` 로 게이트를 걸어둔 건 좋은 조치다
   (`frontend/package.json`). 하지만 이것도 **누군가 로컬에서 실행해야** 의미가 있다.

CI가 없으니 §2의 검증표를 **매번 사람이 손으로 재현**해야 한다. 그리고 이 프로젝트는
이미 그 방식으로 수치가 갈린 전례가 있다(HANDOFF §6.1 — 서브에이전트 개수 보고 3회 불일치).

**최소 워크플로는 §2의 6단계를 그대로 옮기면 된다.** `package-lock.json` 이 커밋돼 있어
`npm ci` 가 바로 동작한다.

한 가지 덧붙이면, `.coderabbit.yaml` 이 **자동 리뷰를 꺼둔 상태**다
(`auto_review.enabled: false`). 의도된 설정으로 보이나(**추정**), 자동 리뷰도 CI도 없으면
**PR에 걸리는 기계적 게이트가 0개**가 된다. 둘 중 하나는 있는 편이 낫다.

---

### C. 문서 신뢰성 — 반복되는 구조적 문제

문서는 성실히 관리되고 있다(`docs/HANDOFF.md` 는 2026-08-18 갱신 블록까지 붙어 있다).
**그런데도 계속 낡는다.** 원인은 게으름이 아니라 **방식**이다 — 스냅샷을 손으로 다시 적고 있다.

증거 세 가지:

**1. `HANDOFF.md` 의 "갱신 블록"이 다시 낡았다.** 8/18 재측정값과 오늘 실측값 비교:

| 항목 | HANDOFF 갱신 블록 (8/18) | **오늘 실측 (9/09)** |
|---|---|---|
| 전체 Go 패키지 | 37 | **48** |
| 테스트 보유 패키지 | 25 | **34** |
| 웹 라우트 | 67 | **74** |
| 비테스트 Go LOC | 12,770 | **18,763** |

**2. `CLAUDE.md` 가 사실과 반대인 문장을 담고 있다.** 현재 이렇게 적혀 있다:

> `internal/webui`, `internal/mcpserver`, `frontend/src` 전체에 테스트가 없다.

`internal/webui` 에는 **테스트 파일이 8개(925줄)** 있다.
`mcpserver`·`frontend/src` 는 맞다. 이 문장은 세션마다 자동으로 주입되므로,
**틀린 전제가 매 작업의 출발점이 된다.**

```bash
ls backend/internal/webui/*_test.go | wc -l    # 8
```

**3. 줄번호 인용이 6일 만에 어긋났다.** 이슈 #50은 `bundleDownload` 를 `webui.go:654` 로 인용했는데,
오늘 실제 위치는 **`webui.go:744`** 다. 이슈 작성(8/21) 이후 6일 만에 90줄 밀렸다.

```bash
grep -n 'func bundleDownload' backend/internal/webui/webui.go   # 744
```

**개선 방향.** 문제는 "문서를 자주 안 고쳐서"가 아니라 **변하는 값을 문서에 손으로 박아서**다.

- **줄번호 대신 심볼 이름으로 인용한다.** `webui.go:744` 대신 `webui.go 의 bundleDownload`.
  줄번호는 커밋마다 밀리지만 함수명은 안 밀린다.
- **수치는 문서에 박지 말고 명령으로 적는다.** 이미 이 레포 문서들은 재현 명령을 병기하는
  좋은 습관이 있다 — 한 걸음 더 가서 **값 자체를 빼고 명령만 남기거나**, CI가 생기면(§3-B)
  거기서 뽑은 값을 자동 갱신하는 게 맞다.
- **`CLAUDE.md` 는 특히 엄격하게.** 자동 주입되는 문서라 틀리면 피해가 가장 크다.
  변하는 사실(테스트 유무 등) 대신 **변하지 않는 규칙**만 남기는 편이 안전하다.
- **미병합 브랜치 `claude/repo-handoff-assessment-lgjz2i` 는 이 작업에 흡수하고 삭제한다**(§1).

---

### D. 테스트 공백 — 외부 표면에 집중돼 있다

전체 34/48 패키지가 테스트를 갖췄다. **문제는 빠진 14개의 성격**이다.

```bash
cd backend && go test ./... 2>&1 | grep 'no test files'
```

| 패키지 | 비테스트 LOC | 왜 중요한가 |
|---|---|---|
| **`internal/mcpserver`** | **831** | **외부 표면.** 툴 56개 노출. §3-A 3번 결함의 현장이며 테스트 0 |
| **`internal/audit`** | 59 | §3-A 1번 결함의 현장. 규제 증적 |
| `internal/ca` | 252 | CA 개인키 생성 + OS 신뢰저장소 변경 |
| `internal/session` | — | 로그인 토큰 발급 |
| `internal/tenant` | — | 프로젝트별 격리 프록시 |
| `internal/config`, `internal/coverage`, `internal/scanlog`, `internal/recon/probe` | — | — |
| `cmd/*` 4개 | — | 바이너리 진입점 (일반적으로 테스트 없음이 정상) |

**`internal/webui` 는 이제 테스트가 있다** — 8개 파일 925줄. 8/10 시점에 "외부 공격면 테스트 0"
이라고 기록했던 것 중 절반이 해소됐다. **남은 절반이 `mcpserver` 다.**

**프론트엔드는 테스트가 0이고 러너 자체가 없다.** `frontend/package.json` 의 `devDependencies` 에
`vitest`/`jest` 가 없다. `src/` 5,913줄이 전부 미검증이며, 유일한 자동 게이트는 `tsc --noEmit` 이다.
타입체크는 "컴파일되는가"만 보고 "동작하는가"는 안 본다.

```bash
git ls-files frontend | grep -iE '\.(test|spec)\.(ts|tsx)$|vitest|jest'   # 0건
```

> **다만 새 러너 도입은 새 의존성 추가다** — CLAUDE.md 워크플로 규칙상 착수 전 합의가 필요하다.
> 우선순위로는 `mcpserver` 테스트가 프론트보다 앞선다고 본다: 인가 결함이 걸려 있고,
> Go 표준 `testing` 만으로 새 의존성 없이 쓸 수 있기 때문이다.

---

### E. 시크릿 위생 — 오늘은 유출 없음, 그러나 방어에 구멍이 있다

**먼저 확실히 해두면, 현재 유출된 시크릿은 없다.** 개인키·마스터키는 트래킹되지 않는다.

다만 `backend/preset-test/` 에 **런타임 상태 파일 10개가 커밋돼 있고, `.gitignore` 가 이를 막지 않는다.**

```bash
git ls-files backend/preset-test/
#   audit.json  ca.crt  checklist.config.yaml  endpoints.json  findings.json
#   local.config.yaml  project.config.yaml  projects.json  scanruns.json  users.json

for f in $(git ls-files backend/preset-test/); do
  git check-ignore -q "$f" && echo "무시됨 $f" || echo "❌ 추적 $f"
done   # 전부 "추적"
```

내용을 확인한 결과 **지금은 안전하다**:

- `local.config.yaml` 의 `api_key` 는 `""` (빈 문자열). 프로바이더가 `ollama`(로컬)라 키가 필요 없다
- `users.json` 의 bcrypt 해시는 README에 공개된 데모 계정(`leader123`/`analyst123`)의 것
- `ca.key`(개인키)는 없고 `ca.crt`(공개 인증서)만 있다

**문제는 값이 아니라 규칙이다.** `.gitignore` 의 상태 파일 규칙이 경로에 고정돼 있다:

```
backend/findings.json          ← backend/ 최상위만
backend/users.json
backend/internal/**/*.json     ← internal 하위만
backend/cmd/**/*.json
```

`backend/preset-test/` 같은 **새 디렉터리는 어느 규칙에도 걸리지 않는다.**
지금은 의도적으로 만든 픽스처라 괜찮지만, 누가 실제 운영 상태를 여기 복사하면
`users.json`(실제 해시)·`projects.json`(AES-GCM 암호화된 인증정보 블롭)이 그대로 커밋된다.

**개선 방향:** 경로 고정 대신 **파일명 기준 전역 규칙**으로 바꾸고, 픽스처는 명시적으로 되살린다.

```gitignore
# 파일명 기준 (어느 디렉터리에 있든)
users.json
projects.json
audit.json
findings.json
# ...
# 의도된 테스트 픽스처만 예외
!backend/preset-test/
!backend/preset-test/*
```

> 단, `.gitignore` 부정 규칙은 과거에 한 번 역효과를 낸 전례가 있으므로
> (HANDOFF §6.4 — 부정 규칙이 실제 빌드 산출물을 추적 대상으로 노출),
> 바꾼 뒤 `git check-ignore -q <path>; echo $?` 의 **종료 코드**로 검증할 것. 출력 유무가 아니다.

---

### F. LLM 비용·한도 제어 부재

LLM은 이 제품의 핵심 판단 엔진이고, 최근 작업이 집중된 영역이다
(판단 프롬프트 정책, 트리아지, fail-open/closed, 추천 배치, 통일 로깅).
**관측은 붙었는데 제어는 아직 없다.**

```bash
grep -rniE 'budget|max_tokens|ratelimit|quota' backend/internal/llm/*.go | grep -v _test
#   anthropic.go:46:  "max_tokens": 2048        ← 이것 하나뿐
```

토큰 상한 하나 외에 **호출 예산·요청 수 제한·동시성 상한이 없다.** 스캔 대상이 커지면
엔드포인트 수에 비례해 호출이 늘어나는 구조라(**추정** — 배치 추천·트리아지 경로가 그렇게 보인다),
외부 프로바이더 사용 시 비용이 예측 불가능해진다.

최근 `d0c7f00`(파라미터 없는 엔드포인트를 LLM 배치에서 제외)이 바로 이 문제를 국소적으로
건드린 커밋이다. **개별 최적화 대신 프로젝트 단위 예산 상한**을 두는 편이 근본적이다.
정찰·스캔에 이미 예산 개념이 있으니(`parammine` 의 예산 소진 테스트) 그 패턴을 재사용할 수 있다.

---

### G. 아키텍처 부채 — 급하진 않으나 누적 중

**1. 상대경로 영속화 (HANDOFF §4-4, 미해결).**

```bash
grep -rn 'const file = "' backend/internal/finding/ backend/internal/audit/
#   finding/finding.go:16  const file = "findings.json"
#   audit/audit.go:22      const file = "audit.json"
```

상태가 프로세스 시작 디렉터리에 종속된다. 다른 디렉터리에서 실행하면 **경고 없이 빈 상태로 시작**한다.
`start-ava-server.vbs` 가 `shell.CurrentDirectory = "C:\AVA\AVA\backend"` 를 명시적으로 설정하는 것이
이 문제의 우회다 — 즉 **이미 실운영에서 부딪힌 적이 있다는 신호**(**추정**).
데이터 디렉터리를 설정값으로 받는 편이 맞다.

**2. `webui.go` 단일 파일 1,606줄.** 라우트 74개가 한 파일에 있다. 테스트는 이미 관심사별로
8개 파일로 쪼개져 있는데(`endpoints_test.go`·`judge_prompt_test.go`·…) **본체만 안 쪼개졌다.**
테스트 파일 분할선이 그대로 좋은 분리 지점이다.

**3. 전역 상태 기반 조립.** DI 없이 패키지 전역 + 세터로 조립하는 구조라,
`webui` 와 `mcpserver` 가 같은 전역 엔진 상태를 조율 없이 각자 바꾼다.
§3-A 3번(MCP 전역 리더 권한)이 이 구조의 직접적 산물이다. 큰 리팩터링이라 지금 권하진 않지만,
**MCP 인증을 설계할 때 이 제약을 먼저 인지해야 한다.**

**4. 번들 크기.** JS 386 kB (gzip 104 kB), 코드 스플리팅 없음. 폐쇄망 단일 바이너리 배포라
네트워크 비용이 크지 않아 **지금은 문제가 아니다.** 계속 커지면 그때 보면 된다.

---

### H. 고아 YAML — 8/10 지적 이후 변화 없음

```bash
git grep -n 'vulndefs' -- 'backend/**'
#   webui.go:141  /api/vulndefs → checklist.Current().Vulns   ← seed.go 런타임 데이터. docs/ 와 무관
git grep -c 'docs/checkitems' -- 'backend/**'   # 0
```

`docs/vulndefs.yaml`·`docs/checkitems.{kii,fin,mobile}.yaml` 4개는 **여전히 런타임이 읽지 않는다.**
스키마도 여전히 비호환이다 — Go 는 스칼라, YAML 은 리스트:

```bash
grep -n 'Vuln .*yaml:"vuln"' backend/internal/checklist/checklist.go
#   66:  Vuln string `yaml:"vuln" json:"vuln"`
sed -n '6,8p' docs/checkitems.kii.yaml
#   vuln:
#   - vuln.os-command
#   - vuln.ldap-injection
```

**대비되는 좋은 사례가 같은 레포에 있다.** `docs/recon-groundtruth/`·`docs/scan-groundtruth/`·
`docs/classify-groundtruth/` 의 YAML은 벤치 코드가 **실제로 읽는다**
(`backend/internal/recon/bench/bench.go:19`). 즉 이 팀은 "문서 옆 YAML을 코드가 소비하는" 패턴을
이미 잘 하고 있다. 점검항목 YAML만 그 대열에 못 들어갔다.

**선택지는 둘 중 하나다:** 스키마를 맞춰 런타임이 읽게 하거나(`Vuln` 을 `[]string` 으로,
`spec.md §6` 의 1:N 설계대로), 혼동을 없애게 **삭제하고 `seed.go` 를 단일 출처로 명시**하거나.
지금처럼 "있는데 안 쓰이는" 상태가 가장 나쁘다 — 고치려는 사람이 매번 여기부터 들여다본다.

---

## 4. 잘 되고 있는 것 (유지할 것)

공정을 기해 적는다. 아래는 **바꾸지 말아야 할 강점**이다.

1. **품질을 숫자로 관리한다.** 정찰·스캔·분류 각각에 벤치 하네스와 정답셋이 붙었다
   (`internal/recon/bench/`, `internal/scanengine/bench/`, `docs/*-groundtruth/`).
   "P 82.8% → 100%" 같은 실측 기록이 커밋 메시지에 남는다. 드문 수준의 규율이다.
2. **테스트가 3배 늘었다** (3,280 → 9,642 LOC). 특히 `internal/webui` 에 8개가 생긴 건
   외부 표면 검증의 출발점이다.
3. **빌드 게이트를 스스로 강화했다.** `"build": "tsc --noEmit && vite build"` 로 타입 에러가
   dist 갱신을 막는다. CI가 없는 상황에서 할 수 있는 최선의 로컬 방어다.
4. **의존성이 여전히 깔끔하다.** 직접 의존성 8개, 8/10 시점과 동일. 기능이 67% 늘어나는 동안
   새 라이브러리를 하나도 안 들였다.
5. **이슈에 "착수 전 합의" 절이 있다.** 이슈 #51이 결정이 필요한 지점 4개를 미리 뽑아둔다.
   설계 논의를 코드 작성 전으로 당기는 좋은 습관이다.

---

## 5. 권장 순서

**순서에 이유가 있다. 뒤 항목이 앞 항목의 검증 수단에 의존한다.**

| 순서 | 작업 | 왜 이 자리인가 | 관련 |
|---|---|---|---|
| **1** | **`CLAUDE.md` 의 틀린 문장 정정** | 자동 주입 문서라 틀린 전제가 매 작업의 출발점이 된다. 수정량 1줄, 위험 0 | §3-C |
| **2** | **CI 워크플로 배선** | 3~5의 "고치기 전/후"를 기계로 비교하려면 먼저 있어야 한다. 이 프로젝트는 이미 수동 검증으로 수치가 갈린 전례가 있다 | §3-B |
| **3** | **`mcpserver`·`audit` 회귀 테스트 선작성** | 이슈 #50을 고치기 전에 현재의 잘못된 동작을 고정해야 "고쳤다"를 증명할 수 있다 | §3-D |
| **4** | **이슈 #50 — 감사 로그 + 번들 ACL** | 국소 수정이고 설계 결정이 없다. `webui` 는 이미 테스트 패턴이 있어 바로 따라 할 수 있다 | §3-A 1·2 |
| **5** | **이슈 #50 — MCP 인증** ★합의 필요 | 토큰/mTLS/소켓 중 선택 + 전역 상태 제약(§3-G 3)이 걸려 착수 전 합의가 필요하다 | §3-A 3 |
| **6** | **`.gitignore` 파일명 기준 전환** | 독립적. 지금 유출은 없으나 방어가 비어 있다 | §3-E |
| **7** | **문서 재생성 방식 전환 + 미병합 브랜치 정리** | 2번이 있으면 수치를 CI에서 뽑을 수 있다 | §3-C, §1 |
| **8** | **LLM 예산 상한** | 기능 확장과 함께 커지는 문제. 급하진 않다 | §3-F |
| **9** | **고아 YAML 결론 내기** (스키마 정합 or 삭제) | 독립적이나 우선순위 낮다 | §3-H |
| **10** | **프론트 테스트 러너** ★합의 필요 | 새 의존성 도입. `mcpserver` 테스트보다 뒤 | §3-D |

★ 표시는 **CLAUDE.md 워크플로 규칙상 착수 전 합의가 필요한 항목**이다
(새 라이브러리·새 추상화 도입).

---

## 6. 이 문서의 한계

- **동적 검증은 하지 않았다.** 서버를 띄워 실제 스캔을 돌리거나, 이슈 #50의 재현 절차
  (재시작 후 `audit.json` 덮어쓰기, 남의 프로젝트 번들 다운로드, 무인증 MCP 호출)를
  **실행해서 확인하지는 않았다.** 정적 근거(코드 위치·함수 부재)로만 판단했다.
  다만 세 건 모두 근거가 명확해 재현될 것으로 본다 — **추정**.
- **프론트 런타임 동작을 보지 않았다.** `tsc --noEmit` 통과와 빌드 성공만 확인했다.
  화면이 실제로 의도대로 도는지는 검증 범위 밖이다.
- **LLM 호출 비용을 실측하지 않았다.** §3-F의 "엔드포인트 수에 비례" 는 코드 구조에서 읽은
  **추정**이며, 실제 호출 횟수를 계측한 값이 아니다.
- **성능·부하를 측정하지 않았다.** 이슈 #51이 지적한 finding 수백~수천 건 시나리오는
  재현하지 않았다.
- 수치는 전부 `d0c7f00` 기준이다. 이후 커밋이 있으면 §2의 명령으로 재측정할 것.
