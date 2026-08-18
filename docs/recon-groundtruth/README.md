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
| `juice-shop.yaml` | SPA (REST) | 31 | 앱 라우트 | 아래 표 기록됨 (+ 정규화 v2 #24 before/after) |
| `dvwa.yaml` | 전통 폼/서버렌더 | 25 | digininja/DVWA 소스 | 아래 표 기록됨(비인증) + #24 회귀 확인 |
| `vampi.yaml` | OpenAPI 명세 API | 14 | erev0s/VAmPI 스펙 | 아래 표 기록됨(#4 전 재현율 낮음 정상) + #24 회귀 확인 |
| `vulnlab.yaml` | 자체 회귀 | (템플릿) | (채워야 함) | 라우트 확정 후 |

## 설계 제약 (중요)

- 채점 매칭은 제품 `endpoints.NormalizePath` 에 **의존하지 않는다**. 정규화 v2(#3)가 그 함수를
  바꾸면 순환 측정이 되기 때문. 하네스는 자체 `Canon()` 규칙만 쓴다
  (`internal/recon/bench/canonical.go` 는 `endpoints` 를 import 하지 않음 = 코드적 보장).
- 제품 정규화 품질은 **트리 팽창률**(제품이 구분한 노드 수 ÷ 하네스 canonical 수, ≥1)로만 관찰한다.
- 정찰은 전역 트리(`endpoints.Default()`)에 기록하므로 프로파일마다 `endpoints.Reset()` 으로 격리한다.

## Baseline (2026-08-14, docker 최신 이미지 — juice-shop / vulnerables/web-dvwa / erev0s/vampi)

| app        | profile   | GT | disc | TP | FP  | FN |   P    |   R    |  F1   | FPrate | infl  | pages |
|------------|-----------|----|------|----|-----|----|--------|--------|-------|--------|-------|-------|
| juice-shop | static    | 31 |  84  | 13 |  71 | 18 | 15.5%  | 41.9%  | 22.6% | 84.5%  | 1.00x |  3    |
| juice-shop | headless¹ | 31 | 231  |  5 | 226 | 26 |  2.2%  | 16.1%  |  3.8% | 97.8%  | 1.20x |  62   |
| dvwa²      | static    | 25 |   2  |  1 |   1 | 24 | 50.0%  |  4.0%  |  7.4% | 50.0%  | 1.00x |  2    |
| dvwa²      | headless  | 25 |   6  |  2 |   4 | 23 | 33.3%  |  8.0%  | 12.9% | 66.7%  | 1.00x |  2    |
| vampi³     | static    | 13 |   0  |  0 |   0 | 13 |  0.0%  |  0.0%  |  0.0% |   —    |  —    |  1    |
| vampi³     | headless  | 13 |   2  |  1 |   1 | 12 | 50.0%  |  7.7%  | 13.3% | 50.0%  | 1.00x |  1    |
| vulnlab    | —         | —  |  —   | —  |  —  | —  |   —    |   —    |   —   |   —    |  —    | (미기동 skip) |

¹ juice-shop headless 는 120s 프로파일 타임아웃에 걸려 **미완료**(pages=62에서 중단).
² dvwa 는 위 표가 **비인증 크롤** — 302 리다이렉트로 대부분 페이지에 못 닿음. 인증 크롤(#31) 결과는 아래 참조.
³ vampi 는 링크 없는 순수 API — 크롤로는 거의 못 찾음 → **스펙 인제스터(#4)** 전까지 재현율 낮음(정상).

### 관찰 (개선 방향 = #3/#4/#5 가 이 수치를 올려야 함)

- **웹 애플리케이션 유형별 강·약점이 드러남**: SPA(juice-shop)는 그나마 재현율 41.9%, 전통 폼(dvwa)은
  인증 벽에 막혀 4~8%, 순수 API(vampi)는 링크가 없어 0~7.7%. → 정찰이 **API·인증 뒤 표면**에 약함.
- **juice-shop static > headless**: headless 는 JS 렌더된 기여자/외부 링크(`/Aashish683`, `/OWASP` 등)를
  엔드포인트로 오수집해 FP 226 → 정밀도 붕괴(2.2%). SPA 라우트·정적자산 필터 부재가 원인.
- **낮은 정밀도(juice-shop 오탐율 84.5%)**: SPA 클라이언트 라우트·정적자산을 엔드포인트로 계상.
  → #3 정규화/필터가 여기서 이득.
- **낮은 재현율(못 찾은 API)**: juice-shop `/api/Products/{id}`·`/rest/products/search`, vampi 전 항목 등.
  → #4 스펙 인제스터·#5 라이브니스가 여기서 이득. dvwa 는 세션(로그인) 주입이 별도 관건.
- **팽창률 대부분 1.00x**: 제품 정규화가 하네스 canonical 만큼 접음(과수집은 필터 문제지 정규화 문제 아님).

### 인증 크롤 (#31) — DVWA before/after

`dvwa.yaml` 에 로그인 시퀀스(admin/password, CSRF `user_token`)를 넣어 **로그인 후 크롤**한 결과.
로그인 뒤에 있던 `/vulnerabilities/*` 에 도달해 재현율이 급등한다.

| dvwa static | disc | TP | FP | FN |   P    |   R    |  F1   |
|-------------|------|----|----|----|--------|--------|-------|
| 비인증(전)  |   2  |  1 |  1 | 24 | 50.0%  |  4.0%  |  7.4% |
| **인증(후)** |  31  | 20 | 11 |  5 | 64.5%  | **80.0%** | **71.4%** |

- 재현율 **4.0% → 80.0%**, F1 **7.4% → 71.4%**. 인증 뒤 표면이 측정 범위에 들어옴.
- headless 는 여전히 낮음(8.0%) — DVWA 는 서버렌더라 헤드리스가 얕게 긁음. static 이 맞는 프로파일.
- 재현: `docker` DVWA 기동 + `setup.php` DB 생성 후 `BENCH_GT=../../../../docs/recon-groundtruth/dvwa.yaml go test ./internal/recon/bench -run ReconBench -v`

### 정규화 v2 (#24) — Juice Shop before/after

`endpoints.NormalizePath` 를 v2(UUID·hash·date·b64 분류기 + 형제 클러스터링)로 교체한 효과.
**이 이슈의 판정 지표는 팽창률**이다(하네스 채점 키는 그대로 — 위 "설계 제약" 참조).

측정: 2026-08-18, `bkimminich/juice-shop:latest`, `http://localhost:3000`.
before = `b5f128a`(v1), after = 정규화 v2. 각각 독립 실행(`-count=1`) 결과.

| juice-shop | disc | TP | FP  | FN |   P    |   R    |  F1   | **infl** | pages |
|------------|------|----|-----|----|--------|--------|-------|----------|-------|
| static  (전) |  84 | 13 |  71 | 18 | 15.5%  | 41.9%  | 22.6% |  1.00x   |  3 |
| static  (후) |  84 | 13 |  71 | 18 | 15.5%  | 41.9%  | 22.6% |  1.00x   |  3 |
| headless (전) | 231 |  5 | 226 | 26 |  2.2%  | 16.1%  |  3.8% |  1.20x   | 58~61 |
| headless (후) | 241 |  5 | 236 | 26 |  2.1%  | 16.1%  |  3.7% | **1.00x** | 60~62 |

전·후 각 4회 독립 실행. **static 은 8회 전부 표의 값과 한 칸도 다르지 않았다.**
headless 는 타임아웃 절단 탓에 before 가 흔들렸고(disc 231 / 216 / 231 / 231, infl 1.20~1.22x),
after 는 4회 모두 disc 241 · infl 1.00x 였다. 위 headless 행은 각각의 최빈값이다.

- **팽창률 headless 1.20x → 1.00x** (목표 ≤ 1.3 충족). 제품 트리가 하네스 canonical 과
  1:1 로 맞는다 = 접히지 않고 남은 가변 세그먼트가 없다. static 은 전부터 1.00x 라 얻을 게 없었다
  (v1 시점 관찰대로 "과수집은 필터 문제지 정규화 문제 아님").
- **재현율 회귀 없음**: static 은 before 와 모든 칸이 동일하고, headless 도 R 16.1% 로 같다.
- headless 정밀도 2.2% → 2.1% 는 정규화 손실이 아니라 **크롤 도달 범위 변화**다. 이 프로파일은
  120s 타임아웃에 잘리는데, v2 의 강한 dedup 으로 크롤러가 중복에 시간을 덜 쓰고 더 멀리 가서
  발견 수 자체가 231 → 241 로 늘었다(FP 226 → 236, TP 는 5 로 동일). juice-shop headless 의 FP 는
  SPA 클라이언트 라우트·기여자 링크이며 필터(#5)의 몫이다.
- static 은 pages=3 으로 크롤이 즉시 끝나 결정론적이다. headless 는 120s 를 다 쓰고 잘리므로
  실행마다 도달 범위가 달라진다 — 회귀 판정을 static 기준으로 보는 이유다.

**재현**

```bash
docker run -d --rm --name js24 -p 3000:3000 bkimminich/juice-shop
cd backend && BENCH_GT=../docs/recon-groundtruth/juice-shop.yaml go test ./internal/recon/bench -run ReconBench -count=1 -timeout 900s -v
```

> `-count=1` 없이 돌리면 두 번째부터 `go test` 결과 캐시에 걸려 **같은 표가 그대로 다시 나온다**
> (실행된 것처럼 보이지만 크롤은 돌지 않았다). before 를 재현하려면 레포를 별도 위치에 clone 해
> `b5f128a` 를 체크아웃한 뒤 같은 명령을 쓴다.

#### DVWA · VAmPI 회귀 확인 (#24)

#24 의 완료기준은 Juice Shop 만 요구하지만, 회귀가 그 앱에만 없다는 보장은 없어 나머지 두 대상도 돌렸다.
**전·후 8행이 한 칸도 다르지 않았다.**

| app · profile   | disc | TP | FP | FN |   P    |   R    |  F1   | infl  | pages |
|-----------------|------|----|----|----|--------|--------|-------|-------|-------|
| dvwa static (전/후)   |  60 | 21 | 39 |  4 | 35.0%  | 84.0%  | 49.4% | 1.02x | 49 |
| dvwa headless (전/후) |  91 | 22 | 69 |  3 | 24.2%  | 88.0%  | 37.9% | 1.01x | 49 |
| vampi static (전/후)   |   0 |  0 |  0 | 13 |  0.0%  |  0.0%  |  0.0% |   —   |  1 |
| vampi headless (전/후) |   2 |  1 |  1 | 12 | 50.0%  |  7.7%  | 13.3% | 1.00x |  1 |

- **DVWA 는 접을 게 없다.** 경로가 `/login.php`·`/vulnerabilities/sqli/` 처럼 전부 고정 문자열이라
  UUID·해시·날짜 세그먼트가 등장하지 않는다. 팽창률이 전·후 모두 1.02x / 1.01x 로 그대로다
  (v2 가 **얻은 것도 잃은 것도 없다** = 회귀 없음).
- **VAmPI 는 측정 자체가 성립하지 않는다.** 링크가 없는 순수 API 라 크롤이 static 0건 / headless 2건만
  찾는다. 분모가 이래서는 팽창률에 의미가 없다. 이건 정규화가 아니라 **스펙 인제스터(#4)** 의 몫이다.
- 정리하면 **정규화 v2 가 실제로 이득을 보는 대상은 Juice Shop 뿐**이었고, 이슈가 Juice Shop 만
  요구한 이유도 이것이다. 나머지 둘에서는 "안 망가졌다"만 확인된다.

> **⚠ 이 DVWA 수치는 위 baseline 표·인증 크롤(#31) 표와 나란히 읽으면 안 된다.**
> 기존 기록은 `vulnerables/web-dvwa`(MySQL 내장) 이미지였는데, 이번 측정은 그 이미지가 로컬에
> 없어 **`ghcr.io/digininja/dvwa:latest` + `mariadb:10`** 조합으로 띄웠다. 라우트 구성이 달라
> 절대 수치가 크게 벌어진다(인증 static 기준 기존 disc 31 · P 64.5% · R 80.0% → 이번 disc 60 ·
> P 35.0% · R 84.0%). **전·후를 같은 컨테이너에 대고 돌렸으므로 회귀 판정에는 영향이 없다.**

재현(이번 구성 그대로):

```bash
docker network create dvwanet24
docker run -d --rm --name dvwadb24 --network dvwanet24 -e MYSQL_ROOT_PASSWORD=dvwa -e MYSQL_DATABASE=dvwa -e MYSQL_USER=dvwa -e MYSQL_PASSWORD='p@ssw0rd' mariadb:10
docker run -d --rm --name dvwa24 --network dvwanet24 -p 8081:80 -e DB_SERVER=dvwadb24 -e DB_DATABASE=dvwa -e DB_USER=dvwa -e DB_PASSWORD='p@ssw0rd' ghcr.io/digininja/dvwa:latest
# DB 생성: /setup.php 에서 user_token 을 뽑아 create_db 를 POST (1회)
docker run -d --rm --name vampi24 -p 5000:5000 erev0s/vampi:latest
```

**단위 테스트** (분류 규칙 20종 이상 — #24 완료기준 1)

```bash
cd backend && go test ./internal/endpoints -run Normalize -v
```

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
  — **미달**. 정규화 v2(#24)는 팽창률만 1.20x → 1.00x 로 내렸고 정밀도는 그대로다(15.5%).
  juice-shop 의 FP 는 값이 다른 중복 노드가 아니라 SPA 클라이언트 라우트·정적자산·외부 링크라
  **정규화가 아니라 필터의 몫**임이 실측으로 확인됐다. `P ≥ 40%` 는 필터/라이브니스(#5)로 넘어간다.
- **#4 스펙 인제스터 후 → 재현율 급등**(명세로 API 발견): `R ≥ 80%`
- **#5 라이브니스 후 → 정밀도 마무리**(죽은/가짜 엔드포인트 제거): `P ≥ 60%`
- **최종: R ≥ 80% · P ≥ 60% · F1 ≥ 0.70 · 팽창률 ≤ 1.2x**
