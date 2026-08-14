# 정찰 벤치마크 정답셋 (#22)

정찰 개선(정규화 v2 #3, 스펙 인제스터 #4, 라이브니스 #5)의 효과와 회귀를 **숫자로** 검증하는 계기판.
"더 많이 찾았다"를 P/R/F1 로 증명한다.

## 정답셋 스키마

```yaml
app: juice-shop
base: https://localhost:3000
endpoints:
  - { method: GET,  path: /rest/products/{id} }
  - { method: POST, path: /api/Feedbacks }
```

- `path` 의 가변 세그먼트는 `{id}` 처럼 아무 이름의 플레이스홀더로 적으면 된다
  (하네스 `bench.Canon` 이 `{}` 로 접어 구체 경로와 매칭).
- 정적 세그먼트는 **대소문자까지 그대로** 비교된다.

## 실행

하네스는 이 폴더의 **`*.yaml` 정답셋을 전부 순회**하며 대상별로 채점한다(#23).
떠 있는 대상만 표를 내고, 미기동 대상은 **skip**(실패 아님).

```bash
# 1) 채점할 대상 웹 애플리케이션을 로컬에 기동 (여러 개 동시에 가능, 서로 다른 포트)
docker run --rm -p 3000:3000 bkimminich/juice-shop     # http://localhost:3000
docker run --rm -p 8080:80   vulnerables/web-dvwa      # http://localhost:8080  (초기 setup.php 1회 필요)
docker run --rm -p 5000:5000 erev0s/vampi              # http://localhost:5000

# 2) 벤치 실행 — 떠 있는 대상 전부 P/R/F1·팽창률 표 출력
cd backend && go test ./internal/recon/bench -run ReconBench -v
```

- 각 정답셋의 `base` 가 **실제 접속되는 프로토콜·포트**인지 확인할 것(안 맞으면 그 대상은 skip).
  self-signed https 는 하네스가 `InsecureSkipVerify` 로 접속만 확인한다.
- `headless` 프로파일은 Chrome/Chromium 이 있을 때만 실행.
- 특정 정답셋 **하나만**: `BENCH_GT=../../../../docs/recon-groundtruth/dvwa.yaml go test ...`
- 정답셋 폴더 변경: `BENCH_GT_DIR=/path/to/dir go test ...`

### 대상 목록 (정답셋)

| 파일 | 성격 | 엔드포인트 | 출처 | baseline |
|------|------|-----------|------|----------|
| `juice-shop.yaml` | SPA (REST) | 31 | 앱 라우트 | 아래 표 기록됨 |
| `dvwa.yaml` | 전통 폼/서버렌더 | 25 | digininja/DVWA 소스 | 기동 후 기록 |
| `vampi.yaml` | OpenAPI 명세 API | 13 | erev0s/VAmPI 스펙 | 기동 후 기록(#4 전 재현율 낮음 정상) |
| `vulnlab.yaml` | 자체 회귀 | (템플릿) | (채워야 함) | 라우트 확정 후 |

## 설계 제약 (중요)

- 채점 매칭은 제품 `endpoints.NormalizePath` 에 **의존하지 않는다**. 정규화 v2(#3)가 그 함수를
  바꾸면 순환 측정이 되기 때문. 하네스는 자체 `Canon()` 규칙만 쓴다
  (`internal/recon/bench/canonical.go` 는 `endpoints` 를 import 하지 않음 = 코드적 보장).
- 제품 정규화 품질은 **트리 팽창률**(제품이 구분한 노드 수 ÷ 하네스 canonical 수, ≥1)로만 관찰한다.
- 정찰은 전역 트리(`endpoints.Default()`)에 기록하므로 프로파일마다 `endpoints.Reset()` 으로 격리한다.

## Baseline (2026-08-14, docker `bkimminich/juice-shop` latest, GT 31개)

| profile  | GT | disc | TP | FP  | FN |   P    |   R    |  F1   | FPrate | infl | pages | time |
|----------|----|------|----|-----|----|--------|--------|-------|--------|------|-------|------|
| static   | 31 |  84  | 13 |  71 | 18 | 15.5%  | 41.9%  | 22.6% | 84.5%  | 1.00x |  3   | 1.5s |
| headless | 31 | 231  |  5 | 226 | 26 |  2.2%  | 16.1%  |  3.8% | 97.8%  | 1.20x |  61  | 120s* |

`*` headless 는 120s 프로파일 타임아웃에 걸려 **미완료**(pages=61에서 중단).

### 관찰 (개선 방향 = #3/#4/#5 가 이 수치를 올려야 함)

- **static > headless**: static 이 API 를 더 많이(R 41.9%) 더 정확히(F1 22.6%) 찾음.
  headless 는 JS 렌더된 기여자/외부 링크(`/Aashish683`, `/OWASP`, `/about` 등)를
  엔드포인트로 오수집해 FP 226 → 정밀도 붕괴(2.2%). SPA 라우트·정적자산 필터 부재가 원인.
- **낮은 정밀도(오탐율 84.5%)**: SPA 클라이언트 라우트(`/address/create`, `/2fa/enter`)와
  정적자산을 엔드포인트로 계상. → #3 정규화/필터가 여기서 이득.
- **낮은 재현율(못 찾은 API)**: `/api/Products/{id}`, `/rest/products/search`, `/rest/languages`,
  `POST /api/BasketItems` 등 다수 누락. → #4 스펙 인제스터·#5 라이브니스가 여기서 이득.
- **팽창률 static 1.00x**: 제품 정규화가 하네스 canonical 만큼 접음(과수집은 필터 문제지 정규화 문제 아님).

## 목표 (합격선 — 개선 성공 판정 기준)

보안(공격면) 도구는 **재현율이 최우선**이다(엔드포인트를 놓치면 그 취약점을 통째로 못 봄).
정밀도(노이즈 적음)도 중요하나 우선순위는 재현율 > 정밀도. 아래는 엔지니어링 목표치이며,
판정은 **가장 좋은 단일 프로파일(현재 static, 향후 passive) 또는 프로파일 합집합** 기준으로 본다.

| 지표        | 지금(static) | 합격선   | 우수   | 근거 |
|-------------|-------------|----------|--------|------|
| 재현율 R    | 41.9%       | **≥ 80%**  | 90%+  | 놓치면 취약점 누락 — 최우선 |
| 정밀도 P    | 15.5%       | **≥ 60%**  | 75%+  | 노이즈(정적자산·SPA 라우트) 제거. recall 우선이라 100%는 목표 아님 |
| F1          | 22.6%       | **≥ 0.70** | 0.80+ | 둘의 균형 |
| 오탐율      | 84.5%       | **≤ 40%**  | ≤25%  | = 1 − 정밀도 |
| 팽창률 infl | 1.00x       | **≤ 1.2x** | ~1.0x | 정규화가 트리를 부풀리면 안 됨(현재 충족) |

### 단계별 목표 (어느 개선이 무엇을 올려야 하는가)

- **#3 정규화/필터 후 → 정밀도 급등**(정적자산·SPA 클라이언트 라우트 제거): `P ≥ 40%`
- **#4 스펙 인제스터 후 → 재현율 급등**(명세로 API 발견): `R ≥ 80%`
- **#5 라이브니스 후 → 정밀도 마무리**(죽은/가짜 엔드포인트 제거): `P ≥ 60%`
- **최종: R ≥ 80% · P ≥ 60% · F1 ≥ 0.70 · 팽창률 ≤ 1.2x**
