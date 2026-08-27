# 의미 분류 벤치마크 정답셋 (이슈 #61 — classify 착수 #41)

`docs/recon-groundtruth/`(#22)·`docs/scan-groundtruth/`(#49)가 정찰·스캔에 해준 것을
의미 분류(`internal/recon/classify`)에도 한다 — **"룰이 실제로 얼마나 맞는가"를 숫자로 잰다.**

이전까지 classify 의 품질 근거는 `classify_test.go` 의 대표 경로 28개 단위 단언뿐이었다(완료기준
"20+"). 단위 테스트는 **내가 고른 예시가 내가 만든 규칙과 맞는지**만 보장한다 — 회귀는 잡지만,
"실제 앱에서 룰이 얼마나 정확한가"는 다른 질문이다. 이 벤치는 그 질문에 답한다.

## classify 는 서버가 필요 없다

정찰·스캔 벤치와 달리 classify 는 **대상에 요청을 보내지 않는 순수 함수**다(구조적 입력 →
라벨). 그래서 이 벤치는 docker 컨테이너나 살아있는 서버 없이 즉시 돈다.

## 정답셋 재사용 — 동어반복을 피한다

`docs/classify-groundtruth/juice-shop.yaml` 의 엔드포인트는 `docs/recon-groundtruth/juice-shop.yaml`
(#61 로 64개 실재 확인)을 그대로 가져왔다. **`expect` 라벨은 classify 의 키워드 사전을 보지 않고
사람이 각 라우트의 실제 목적만 보고 독립적으로 판단**했다 — 사전을 베끼면 벤치가 "룰이 룰과
같은지"만 재는 동어반복이 된다. 사전에 없는 단어로 걸리는 사례(`whoami`·`metrics`·
`dataerasure`·`security-question`·`saveLoginIp`)를 일부러 섞어 룰의 사각지대가 드러나게 했다.

## 채점 — 의미 라벨만 본다

라벨은 9종이지만 스코어는 **의미 라벨 6종(auth·payment·upload·admin·pii·search)만** 본다.
구조 라벨(api·static)은 경로에 `rest`/`api`/`vN` 세그먼트나 정적 확장자가 있으면 기계적으로
참이 되어, 스코어에 넣으면 사실상 "경로 문자열 매칭"만 재는 것이 된다. 규제 매핑(#42)·스캔
우선순위가 실제로 소비하는 건 의미 라벨이라 이게 의미 있는 지표다.

- **쌍 단위 micro P/R/F1** — 엔드포인트마다 여러 라벨을 가질 수 있어(다중 라벨), (엔드포인트,라벨)
  쌍을 정찰 벤치의 (메서드,경로) 쌍과 같은 방식으로 채점한다.
- **TP** = 예측·정답 둘 다에 있는 라벨. **FP** = 예측에만. **FN** = 정답에만.
- `expect: []` (의미 라벨 없음)인 항목은 예측도 의미 라벨이 없어야 맞힌 것으로 친다 — 틀리면 FP.

## 실행

```bash
cd backend && go test ./internal/recon/classify/bench -run ClassifyBench -v -count=1
```

특정 정답셋만: `CLASSIFYBENCH_GT=../../../../../docs/classify-groundtruth/juice-shop.yaml go test ...`
LLM 포함: `CLASSIFYBENCH_LLM=mock|ollama|anthropic|openai`(+`_MODEL`/`_ENDPOINT`/`_KEY`). 미설정이면
프로바이더를 건드리지 않아 **룰만** 채점한다 — 이번 baseline이 그 경우다.

## Baseline (2026-08-27, 커밋 `e3e31d0` 이후, 룰 전용 — LLM 미설정)

| app | 엔드포인트 | 쌍 | TP | FP | FN | P | R | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| juice-shop | 63 | 51 | 19 | 8 | 24 | 70.4% | 44.2% | 54.3% |

재현: 위 명령 그대로(대상 서버 불필요).

### 발견 — 룰의 사각지대 2종 (수정은 다음 이슈로 이월)

정찰 벤치가 #22(계기판)와 #24(개선)를 별도 이슈로 나눈 것과 같은 이유로, 이번 이슈는 **계기판
신설과 baseline 기록까지만** 한다 — 발견한 결함을 곧장 고치면 "내가 방금 만든 벤치가 내가 방금
바꾼 규칙과 맞는지"를 재는 순환이 되기 쉽고, 라벨링 정책(아래 참조)에 대한 합의 없이 프로덕션
규칙을 바꾸는 것도 성급하다. 대신 재현 가능한 형태로 남긴다.

**① `user` 키워드가 너무 넓다.** PII 룰의 `user` 키워드가 `/rest/user/*` 아래 모든 라우트에
걸린다 — 로그인(`login`)·비밀번호 재설정(`reset-password`)처럼 이미 `auth` 룰로 잡히는 것도
**동시에** `pii` 로 잘못 태깅된다(오탐 8건 중 6건이 이 패턴). 예: `POST /rest/user/login` →
룰 예측 `[auth, pii]`, 내 판단은 `[auth]`뿐. **다만 이건 룰이 "틀렸다"기보다 라벨링 정책의
문제일 수 있다** — 로그인도 결국 사용자 개인 계정에 접근하는 행위라 `pii` 동시 태깅이 완전히
틀린 것은 아니다. 정답셋이 "주 목적 하나"만 골랐는데 룰은 "관련된 것 전부"를 잡는 방식이라
생긴 불일치일 수 있어, 고치기 전에 **다중 라벨을 어디까지 허용할지 합의**가 필요하다.

**② 결제성 키워드 사전 공백.** `basket`(장바구니)·`membership`(유료 멤버십) 이 Payment
키워드 사전에 없다. `GET /rest/basket/{id}`·`GET /api/BasketItems`·`GET /rest/deluxe-membership`
가 전부 라벨 없음(`[]`)으로 나온다(누락 24건 중 6건이 이 패턴). 이건 라벨링 정책과 무관하게
**명백한 사전 공백**이라 다음 이슈에서 안전하게 고칠 수 있는 후보다.

**③ 사전에 없는 단어 6개는 대부분 놓쳤다** — 의도한 대로다. `whoami`·`security-question`·
`saveLoginIp`·`Continue Code` 계열(6개)·`metrics`·`dataerasure` 모두 룰 사전에 그 단어가 없어
FN 으로 잡혔다. 이게 "실 LLM 평가"(HANDOFF #40·#41 절)가 메워야 할 몫이다 — 프로바이더를
설정해 `CLASSIFYBENCH_LLM=ollama` 등으로 재측정하면 이 사각지대가 얼마나 줄어드는지 잴 수 있다.

## 한계

- **정답셋은 juice-shop 하나뿐이다.** vampi·dvwa 는 `docs/recon-groundtruth/`에 이미 있지만
  아직 라벨을 안 달았다 — 후속.
- **`expect` 는 사람이 고른 "주 라벨"이다.** 다중 라벨 정책(위 발견 ①)이 정해지기 전에는
  P/R 절대값보다 **회귀 여부**(같은 정답셋으로 재측정했을 때 나빠지지 않았는가)가 더 안정적인
  신호다.
- **LLM 비교는 프로바이더가 설정돼야 나온다.** 이번 baseline은 룰 전용이다.
