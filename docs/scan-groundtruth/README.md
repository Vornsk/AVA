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
*(측정 대기 — 아래 "기록 방법" 참고)*
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
  비교가 무의미해 skip 한다(`local.config.yaml` 의 `llm.provider`).
- **LLM 재현 입력이 제품보다 얇다.** 하네스는 발견을 모은 뒤 판정을 얹는데, 이때
  `Evidence`·`Request`·`Response` 를 다시 만들지 않는다. 제품 실행(`scanengine.execute`)은
  증적 전체를 넘기므로, 벤치의 LLM 판정은 **제품보다 보수적으로** 나올 수 있다.
- **정답셋은 우리가 만든 앱 2종뿐이다.** 닫힌 세계라 정답이 정확한 대신, 실제 웹앱의
  다양성(프레임워크·WAF·SPA)은 반영되지 않는다. 외부 앱(juice-shop·DVWA) 추가는 후속 과제.
- **`vulnlab` 에는 정상 대조군이 없다.** FP 분모는 `vulnapp` 의 `-safe` 계열이 담당한다.
  vulnlab 지표는 재현율 위주로 읽을 것.
