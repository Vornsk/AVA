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

```bash
# 1) 대상 앱을 로컬에 기동 (예: Juice Shop)
docker run --rm -p 3000:3000 bkimminich/juice-shop     # http://localhost:3000
# (정답셋 base 가 https 면 그에 맞게. self-signed 는 하네스가 InsecureSkipVerify 로 접속 확인)

# 2) 벤치 실행 — P/R/F1·팽창률 표 출력
cd backend && go test ./internal/recon/bench -run ReconBench -v
```

- 대상이 미응답이면 테스트는 **skip** (실패 아님).
- `headless` 프로파일은 Chrome/Chromium 이 있을 때만 실행.
- 다른 정답셋을 쓰려면: `BENCH_GT=/path/to/gt.yaml go test ...`

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
