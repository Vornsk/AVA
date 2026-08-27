# 스캔 벤치마크 정답셋 (이슈 #49)

정찰 벤치(#22, `docs/recon-groundtruth/`)가 정찰에 해준 것을 스캔에 한다 —
**detector 를 고치거나 추가할 때 "좋아졌다 / 회귀 없다"를 숫자로 말하기 위한 계기판.**

이전까지 스캔 품질의 근거는 `detector_test.go` 의 케이스별 단위 단언뿐이었다. 회귀는 잡지만
집계 지표를 못 낸다. 그래서 **이 도구의 오탐률이 몇 %인지 아무도 말할 수 없었다.**

---

## 실행

```bash
cd backend && go test ./internal/scanengine/bench -run ScanBench -v -count=1
```

> **`-count=1` 을 꼭 붙일 것.** 정답셋 YAML 은 패키지 밖(`docs/`)에 있어 go test 캐시가
> 변경을 감지하지 못한다. 빼먹으면 YAML 을 고쳐도 **이전 실행 결과가 그대로 재출력된다**
> (`ok ... (cached)` 표시로 알아챌 수 있다).

| 대상 | 준비 | 비고 |
|---|---|---|
| `vulnlab` | **불필요** | `http.Handler` 라 하네스가 `httptest` 로 인프로세스 기동. 항상 채점된다 |
| `vulnapp` | `cd backend && go run ./cmd/vulnapp` | 기본 `127.0.0.1:9099`. 미기동이면 skip(실패 아님) |

특정 정답셋만: `SCANBENCH_GT=../../../../docs/scan-groundtruth/vulnapp.yaml go test ... -count=1`
폴더 변경: `SCANBENCH_GT_DIR=/path/to/dir`
실행 예산: `SCANBENCH_TIMEOUT=50m` (기본 40m)

### 오래 걸린다 — 그리고 잘리면 실패한다

`vulnapp` 은 대상 21개 × detector 23종에 더해 `sqli-time` 이 **대상이 실제로 잠들기를 기다리고**,
`idor`·`privesc` 가 신원 수만큼 요청을 곱한다. 십수 분 규모다. `go test -timeout` 도 넉넉히 줄 것.

예산이 모자라면 **부분 결과로 채점하지 않고 테스트가 실패한다.** 이건 의도된 동작이다 —
이 하네스의 초기 실행이 10분 타임아웃에 잘려 `csrf`·`cookie-security`·`http-method`·
`dir-indexing` 이 통째로 빠진 채 `P=100%` 를 자신 있게 출력한 적이 있다.
계기판이 조용히 절단되면 계기판이 아니라 거짓말이 된다.

정답셋 자체의 스키마·참조 무결성은 대상 없이도 검사된다:

```bash
cd backend && go test ./internal/scanengine/bench -run 'Score|GroundTruth|SiteWide|VulnDef'
```

---

## 채점 규칙 (이슈 #49 착수 전 합의)

### ① 측정 범위 — 스캔만 격리한다

정답셋의 대상 목록으로 `endpoints.Target` 을 **직접 시드**하고 크롤을 돌리지 않는다.
정찰을 앞에 끼우면 정찰이 못 찾은 경로가 스캔의 FN 으로 잡혀 detector 탓이 된다.
정찰 품질은 `recon/bench` 가 따로 잰다. 부수 효과로 실행이 결정론적이 된다.

### ② 오탐(FP) — 정상 케이스에서 발동한 것만

| 분류 | 정의 |
|---|---|
| **TP** | 정답셋의 `expect` 에 적힌 (경로, 취약점) 조합이 발견됨 |
| **FP** | 정답셋의 `not_expect` 에 적힌 조합이 발견됨 — **정상 구현인데 발동** |
| **미분류** | 정답셋에 언급이 없는 발견. **오탐으로 세지 않는다** |
| **전역** | `site_wide` 취약점(예: 보안 헤더 누락). 채점에서 제외 |
| **측정불가** | 담당 detector 가 이번 실행에서 빠짐(파괴성 등). **GT 분모에서도 제외** |

`P = TP / (TP+FP)` — 미분류는 분모에 넣지 않는다. 그래야 FP율이 정답셋 큐레이션 누락에
휘둘리지 않는다. 대신 **미분류 목록이 곧 정답셋을 넓히라는 작업 목록**이다.
(구성상 `FPRate = 1 - P` 다. 두 값을 다 찍는 건 정찰 벤치와 표 형식을 맞추기 위한 것.)

**측정불가**를 따로 둔 이유: `/upload` 의 `vuln.file-upload` 는 담당 detector 가 파괴성이라
기본 실행에서 빠진다. 이걸 FN 으로 세면 detector 가 못 찾은 것처럼 보여 재현율이 거짓으로
낮아진다. 하네스 정책으로 빠진 것과 detector 가 놓친 것은 다르다.

### ③ 매칭 단위 — (경로, VulnDef) 쌍

도출리스트(FR-4.1)가 이 단위로 건수를 세므로 리포트 숫자와 일치한다.
같은 취약점이 파라미터 3개에서 잡혀도 1건이다. 경로는 정찰 벤치의 `Canon` 으로 접어
구체 경로(`/item/42`)와 정답(`/item/{id}`)이 매칭된다.

detector 별 분해만 **발견 단위**(접기 전)로 낸다 — 어느 탐지기가 오탐을 만드는지 지목하려면
쌍으로 접으면 안 되기 때문이다.

---

## 정답셋 작성법

```yaml
targets:
  - path: /profile
    methods: [GET]
    auth: true
    expect: [vuln.info-exposure]      # 나와야 하는 것
    not_expect: [vuln.access-control] # 나오면 오탐인 것
    note: 민감정보는 평문(취약)이나 접근통제 자체는 정상.
```

한 경로에 `expect` 와 `not_expect` 를 같이 둘 수 있다. 위가 그 예다 — 이 표현력이 없으면
"부분적으로만 취약한 엔드포인트"를 정답셋에 담을 수 없다.

**`identities` 를 빠뜨리지 말 것.** `idor`·`privesc` detector 는 신원이 2개 미만이면 조용히
`nil` 을 반환한다. 수직 권한상승까지 재려면 `privileged: true` 신원과 저권한 신원이 모두
있어야 한다. 이걸 안 넣으면 접근통제 계열 전체가 측정에서 빠지고 그 정답이 전부 FN 으로
잡힌다 — 실제로 이 하네스의 첫 실행에서 그 함정에 빠졌다.

`expect` 와 `not_expect` 에 같은 id 가 들어가면 로드 시점에 에러다(채점 모순 방지).
존재하지 않는 VulnDef id 도 `TestGroundTruthFilesValid` 가 잡는다.

---

## 베이스라인

<!-- BASELINE:START -->

### 2026-08-21 · 최초 측정

- 커밋: 스캔 지표는 `dd015a2` · LLM 절은 `2fef08f` 기준 (브랜치 `seona`)
- 환경: Go 1.26.5 windows/amd64 · 외부 도구 `sslscan` 미설치(해당 detector 는 스킵)
- LLM 트리아지는 `mock` 프로바이더로만 측정 — 실 모델 미측정(아래 절 참고)

| 대상 | GT | 발견 | TP | FP | FN | 미분류 | P | R | F1 | FP율 | 소요 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `vulnapp` | 16 | 23 | 16 | 3 | 0 | 4 | 84.2% | 100.0% | 91.4% | 15.8% | 3m31s |
| `vulnlab` | 8 | 10 | 8 | 2 | 0 | 0 | 80.0% | 100.0% | 88.9% | 20.0% | 50s |
| **합산**¹ | 24 | 33 | 24 | 5 | 0 | 4 | **82.8%** | **100.0%** | **90.6%** | **17.2%** | — |

¹ 합산은 하네스가 내는 값이 아니라 두 행의 TP·FP 를 더해 수기 계산한 것이다.
`P = 24/(24+5) = 82.8%`, `R = 24/24 = 100%`.

그 밖에: 전역(`vuln.sec-headers`) 27쌍은 채점 제외, 측정불가 1쌍(`/upload vuln.file-upload`
— 담당 detector 가 파괴성이라 GT 분모에서 제외).

**재현:**

```bash
cd backend && go run ./cmd/vulnapp &          # vulnlab 은 인프로세스라 준비 불필요
cd backend && SCANBENCH_TIMEOUT=50m go test ./internal/scanengine/bench \
  -run ScanBench -v -count=1 -timeout 90m
```

### 이 수치를 어떻게 읽을 것인가

- **재현율 100%** — 정답 24쌍을 하나도 놓치지 않았다. 다만 정답셋이 **우리가 만든 앱 2종**이라
  detector 가 이 앱들에 맞춰 개발된 면이 있다. 외부 앱을 넣기 전까지 재현율은 상한에 가깝게
  나올 것으로 보는 게 맞다.
- **오탐 5건이 전부 `reflected-input` 하나에서 나왔다.** 다른 12개 detector 의 FP 는 0이다.
  → 오탐 문제는 "스캐너 전반"이 아니라 **한 detector 의 한 가지 결함**으로 좁혀졌다.
- **`reflected-input` 자체의 오탐률은 절반이다** (vulnapp TP=4/FP=4, vulnlab TP=2/FP=2).
  원인은 하나다 — **응답 Content-Type 을 보지 않는다.** `text/plain` 응답에 반사된 입력은
  브라우저가 실행하지 않으므로 XSS 가 아닌데도 보고한다.
  해당 5건: `/exec`·`/fetch`(vulnlab), `/transfer`·`/change-email`·`/download`(vulnapp).
  전부 `curl -D-` 로 Content-Type 을 직접 확인했다.
  **이걸 고치면 합산 P 가 82.8% → 100% 가 된다** — 다음 개선의 1순위이자, 이 벤치의 첫 성과다.
  → **2026-08-24 이슈 #54 에서 실측으로 확인됨**(아래 절). 예측한 수치가 그대로 나왔다.

### LLM 트리아지 전후 (FR-3.3) — 프로바이더 `mock`

| 대상 | FP | TP | P | LLM 이 오탐 표시 | 잘 걸러냄 | ★ 정탐 삭제 |
|---|---:|---:|---:|---:|---:|---:|
| `vulnapp` | 3 → 3 | 16 → 16 | 84.2% → 84.2% | 0건 | 0 | 0 |
| `vulnlab` | 2 → 2 | 8 → 8 | 80.0% → 80.0% | 0건 | 0 | 0 |

**측정 결과: mock 트리아지는 오탐을 한 건도 줄이지 못했다. 대신 정탐도 지우지 않았다.**

재현: 위 명령에 `SCANBENCH_LLM=mock` 을 붙인다.

**왜 0건인가 — 배관이 아니라 규칙 때문이다.** `TestReviewLLMCarriesEvidence` 로 확인한 결과,
증적을 실어 보내면 mock 은 인코딩 반사(`&lt;script&gt;`)와 `textarea` 반사를 정확히 오탐으로
판정한다. 즉 전달은 정상이다. 문제는 **mock 의 오탐 규칙이 모델링하는 실패 유형과 우리가
실제로 가진 오탐 유형이 다르다**는 것이다 —

- mock 이 아는 오탐: 값이 **인코딩되어** 반사되거나 **비실행 컨테이너**(textarea·주석) 안에 있음
- 우리 오탐 5건: 값이 **raw 로** 반사되지만 응답이 `text/plain` 이라 브라우저가 실행 안 함

mock 은 Content-Type 을 보지 않으므로 이 유형을 잡을 수 없다. `reflected-input` detector 와
**정확히 같은 맹점**이다.

> ⚠️ **이 표로 "LLM 트리아지가 쓸모없다"고 결론지으면 안 된다.** mock 은 문자열 휴리스틱이지
> 언어모델이 아니다. `reviewSysPrompt` 는 실제 모델에게 응답 문맥을 추론하라고 지시하므로,
> 실 모델이라면 `text/plain` 이라는 사실로부터 실행 불가를 추론할 여지가 있다.
> **그 질문의 답은 아직 측정되지 않았다.**

실 모델로 재측정:

```bash
cd backend && SCANBENCH_LLM=ollama SCANBENCH_LLM_MODEL=llama3.2 \
  SCANBENCH_LLM_ENDPOINT=http://127.0.0.1:11434 \
  SCANBENCH_TIMEOUT=50m go test ./internal/scanengine/bench -run ScanBench -v -count=1 -timeout 90m
```

`SCANBENCH_LLM` 은 `mock|ollama|anthropic|openai` 를 받는다(`SCANBENCH_LLM_KEY` 로 API 키).
테스트 바이너리는 `local.config.yaml` 을 읽지 않으므로 프로바이더는 이 환경변수로만 지정된다.

**★ 정탐 삭제 열을 반드시 같이 볼 것.** 오탐만 줄었는지 보면 절반만 보는 것이다 —
정탐까지 지우면 오탐률은 좋아지고 도구는 나빠진다. 이번 측정은 그 열이 0이라 안전하다.

### 남은 미분류 4건 (판단 보류)

| 쌍 | 왜 보류인가 |
|---|---|
| `/download vuln.code-injection`<br>`/download vuln.ssrf` | vulnapp 이 `file` 값에 `passwd` 가 들어있기만 하면 무조건 passwd 를 뱉는다. 그래서 `;cat /etc/passwd`·`file:///etc/passwd` 페이로드에도 반응한다. **실제 LFI 앱이라면 그런 이름의 파일이 없어 안 나온다** → detector 결함이 아니라 테스트 앱 충실도 문제일 가능성이 크다. vulnapp 의 LFI 를 실제 경로 해석으로 바꾼 뒤 재판정할 것 |
| `/transfer vuln.access-control`<br>`/transfer vuln.ssrf` | 아직 근거를 확보하지 못했다. 정탐인지 오탐인지 실측으로 가르기 전에는 정답셋에 넣지 않는다 |

미분류를 근거 없이 `expect`/`not_expect` 로 옮기면 계기판이 아니라 자기충족 예언이 된다.
### 2026-08-24 · 이슈 #54 — 트리아지 프롬프트 + detector Content-Type 수정

- 커밋: 트리아지 `8d07401`·`950c393` · detector `b260943` (브랜치 `seona`)
- 환경: Go 1.26.5 windows/amd64 · 외부 도구 `sslscan` 미설치 · LLM 은 ollama(CPU)
- **위 최초 측정의 예측이 맞았다.** "오탐 5건이 전부 `reflected-input` 의 Content-Type 미검사 —
  고치면 합산 P 82.8% → 100%" 가 실측으로 확인됐다.

#### 스캔 지표 (detector 수정 후)

| 대상 | GT | 발견 | TP | FP | FN | 미분류 | P | R | F1 | FP율 | 소요 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `vulnapp` | 16 | 20 | 16 | 0 | 0 | 4 | 100.0% | 100.0% | 100.0% | 0.0% | 3m32s |
| `vulnlab` | 8 | 8 | 8 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% | 0.0% | 50s |
| **합산** | 24 | 28 | 24 | 0 | 0 | 4 | **100.0%** | **100.0%** | **100.0%** | **0.0%** | — |

`reflected-input` 이 `TP=4 FP=4` → `TP=4 FP=0`(vulnapp), `TP=2 FP=2` → `TP=2 FP=0`(vulnlab).
**정탐은 하나도 잃지 않았다** — 미디어타입 미상(Content-Type 헤더 없음)은 브라우저가 스니핑하므로
발견을 유지하도록 했기 때문이다. 지우는 조건은 "렌더링하지 않는다고 확인된 경우"뿐이다.

#### LLM 트리아지 전후 (FR-3.3) — detector 수정 **전** 상태에서 측정

detector 를 고치기 전에 재야 트리아지 효과를 잴 수 있다. 고친 뒤엔 걸러낼 오탐이 0이라
"트리아지가 detector 의 실수를 잡는가"라는 질문 자체가 성립하지 않는다.

| 프로바이더 | 대상 | FP | TP | P | 오탐 표시 | 잘 걸러냄 | ★ 정탐 삭제 |
|---|---|---:|---:|---:|---:|---:|---:|
| `mock`(#49) | 합산 | 5 → 5 | 24 → 24 | 82.8% → 82.8% | 0건 | 0 | 0 |
| `qwen2.5:3b` | vulnapp | 3 → 0 | 16 → 11 | 84.2% → 100.0% | 14 | 4 | **5** |
| `qwen2.5:3b` | vulnlab | 2 → 0 | 8 → 5 | 80.0% → 100.0% | 8 | 2 | **3** |
| `qwen2.5:7b` | vulnapp | 3 → 0 | 16 → 16 | 84.2% → 100.0% | 13 | 4 | **0** |
| `qwen2.5:7b` | vulnlab | 2 → 1 | 8 → 8 | 80.0% → 88.9% | 4 | 1 | **0** |

**결론: 트리아지에는 `qwen2.5:7b` 가 필요하다. 3b 는 오탐을 지우면서 정탐도 8건 지운다.**
7b 합산은 FP 5 → 1, TP 24 → 24, P 82.8% → 96.0%, **정탐 손실 0건**.

판단(Judge) 스테이지 권장이 3b 인 것(`main` e317d97·42cd6e7)과 모순이 아니다. 태스크가 다르고
실패 방향이 반대다 — 판단에서 7b 의 오답은 false-allow(위험), 트리아지에서 3b 의 오답은
과잉 삭제(정탐 손실)다. 대가는 속도다: vulnapp 트리아지가 7m49s(3b) → 13m20s(7b), 약 1.7배.

#### detector 수정까지 반영한 최종 측정 (`qwen2.5:7b`)

| 대상 | FP | TP | P | ★ 정탐 삭제 |
|---|---:|---:|---:|---:|
| `vulnapp` | 0 → 0 | 16 → 16 | 100.0% → 100.0% | 0 |
| `vulnlab` | 0 → 0 | 8 → 8 | 100.0% → 100.0% | 0 |

detector 가 이미 걸러서 트리아지가 지울 오탐이 없다. **두 방어선이 독립적으로 같은 결함을 막는다** —
detector 가 새 우회를 만나 놓쳐도 트리아지가 잡고, 트리아지 모델이 약해도 detector 가 잡는다.
(트리아지가 표시한 9·4건은 전부 미분류/전역이라 채점에 들어가지 않는다.)

#### 프롬프트 1차 판본은 실패했다 — 기록해 둔다

detector 별 힌트를 "이 탐지기는 이렇게 헛발질한다"로만 써서 **오탐 조건만 나열하고 정탐 조건을
안 적었다.** 그랬더니 3b 가 `reflected-input` 을 통째로 오탐 처리했다(vulnapp `TP=4 FP=4` →
`TP=0 FP=1`). 배선 문제가 아니었다 — `/search=text/html`·`/download=text/plain` 로 `content_type`
은 정확히 전달됐다. 모델이 신호를 읽는 대신 힌트의 방향에 끌려간 것이다.

판단 프롬프트가 겪은 실패와 같은 모양이다(`main` e317d97: 기준 없이 쓰니 전건 차단, 4/10).
같은 처방으로 고쳤다 — 모든 힌트를 `REAL when … / FALSE POSITIVE when …` **대칭**으로, 기본 방향
명시(`Default to real`), 예시 3건 중 정탐을 맨 앞에. `TestTriageHintsAreSymmetric` ·
`TestTriagePromptDefaultsToKeeping` 이 이 회귀를 막는다.

#### 재현

```bash
cd backend && go run ./cmd/vulnapp &
cd backend && SCANBENCH_LLM=ollama SCANBENCH_LLM_MODEL=qwen2.5:7b \
  SCANBENCH_LLM_ENDPOINT=http://127.0.0.1:11434 \
  SCANBENCH_TIMEOUT=50m go test ./internal/scanengine/bench -run ScanBench -v -count=1 -timeout 120m
```

트리아지 효과를 다시 보려면 `b260943`(detector 수정) 이전 커밋에서 돌려야 한다.

#### 아직 측정하지 않은 것

- **Claude(anthropic) 프로바이더 미측정 — 이슈 #62 에서도 키 미확보로 재확인(2026-08-27).**
  API 키가 설정돼 있지 않다(`local.config.yaml` 의 `provider: ollama`, `api_key` 가 빈 값).
  이슈 #62 착수 시 키 확보 여부를 확인했고, **키가 없어 실측하지 않기로 결정**했다(비용·키 노출
  회피). 키가 생기면 아래 명령으로 이 표에 행을 추가할 것:

  ```bash
  cd backend && go run ./cmd/vulnapp &
  cd backend && SCANBENCH_LLM=anthropic SCANBENCH_LLM_KEY=<키> SCANBENCH_LLM_MODEL=claude-... \
    SCANBENCH_TIMEOUT=50m go test ./internal/scanengine/bench -run ScanBench -v -count=1 -timeout 120m
  ```

  이슈 #54·#62 의 완료 기준 중 이 항목은 **키 미확보 사유 기록으로 갈음**한다(#62 완료기준이
  "벤치 수치 기록 또는 키 미확보 사유 기록"으로 대안을 명시).
- **제품에서 LLM 판정은 주석일 뿐 상태를 바꾸지 않는다**(`scanengine.execute`, HITL).
  위 "정탐 삭제" 수치는 **판정을 그대로 믿고 필터링했다면** 의 가정값이며, 실제로 발견이
  사라지지는 않는다. 그래도 배지·필터의 신뢰도를 그대로 나타내므로 계기판으로서 유효하다.

<!-- BASELINE:END -->

### 기록 방법

측정할 때마다 이 절에 **날짜·커밋·환경**과 함께 표를 갱신한다. 수치만 적고 재현 명령을
안 적으면 다음 사람이 검증할 수 없다(CLAUDE.md 검증 규칙).

이 저장소에는 CI 워크플로가 없어(HANDOFF §3 ②) 임계값 게이트를 걸 곳이 없다.
그래서 **기록만 한다** — 회귀 판단은 사람이 표를 비교해서 한다. CI 가 생기면
이 표의 값을 임계값으로 승격하는 것이 다음 단계다.

---

## 한계

- **LLM 트리아지 비교는 프로바이더가 설정돼야 나온다.** 없으면 판정이 전부 `uncertain` 이라
  비교가 무의미해 skip 한다(`SCANBENCH_LLM` 환경변수).
- **트리아지는 모델을 가린다.** `mock`(0건 검출)·`qwen2.5:3b`(오탐은 줄이나 정탐 8건 삭제)·
  `qwen2.5:7b`(정탐 손실 0건)를 측정했다. **Claude(anthropic)는 API 키가 없어 미측정**이다.
  위 2026-08-24 절 참고.
- **정답셋은 우리가 만든 앱 2종뿐이다.** 닫힌 세계라 정답이 정확한 대신, 실제 웹앱의
  다양성(프레임워크·WAF·SPA)은 반영되지 않는다. 외부 앱(juice-shop·DVWA) 추가는 후속 과제.
- **`vulnlab` 에는 정상 대조군이 없다.** FP 분모는 `vulnapp` 의 `-safe` 계열이 담당한다.
  vulnlab 지표는 재현율 위주로 읽을 것.
