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
| `juice-shop.yaml` | SPA (REST) | 38 | 앱 라우트 | 아래 표 기록됨 (+ #24 · #25 · #26 · #27 before/after) |
| `dvwa.yaml` | 전통 폼/서버렌더 | 25 | digininja/DVWA 소스 | 아래 표 기록됨(비인증) + #24 · #25 · #26 before/after |
| `vampi.yaml` | OpenAPI 명세 API | 14 | erev0s/VAmPI 스펙 | 아래 표 기록됨 + **#25 로 R 0% → 100%** · #26 무변화(전부 spec) |
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
**정답셋 기준: juice-shop 31개** (이후 #25 로 32, #26 으로 34 가 됐다 — FN·재현율은 그 시점 GT 기준으로 읽을 것).

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

### 스펙 인제스터 (#25) — 3개 대상 before/after

명세(robots/sitemap/OpenAPI/GraphQL/소스맵)를 읽어 엔드포인트를 얻는 인제스터를 붙인 효과.
**이 이슈의 판정 지표는 재현율**이다. `ingest` 프로파일은 크롤을 돌리지 않아 "명세만으로 얼마나
찾는가"를 격리 측정하고, `static`·`headless` 는 크롤 시작 시 명세를 1회 선행 인제스트한다.

측정: 2026-08-18. before = `0af9a08`(#24 머지 시점), after = 스펙 인제스터.
**정답셋 기준: juice-shop 32 · vampi 14** (이후 #26 으로 juice-shop 이 34 가 됐다).
**before 도 갱신된 정답셋으로 다시 돌려** 같은 기준에서 비교했다(아래 정답셋 변경 참조).

| 대상 · 프로파일 | disc | TP | FP  | FN |   P    |   R    |  F1   |
|-----------------|------|----|-----|----|--------|--------|-------|
| **vampi** ingest (후)   |  14 | 14 |   0 |  0 | **100.0%** | **100.0%** | **100.0%** |
| vampi static (전)       |   0 |  0 |   0 | 14 |   0.0% |   0.0% |   0.0% |
| **vampi static (후)**   |  13 | 13 |   0 |  1 | **100.0%** | **92.9%** | **96.3%** |
| vampi headless (전)     |   2 |  1 |   1 | 13 |  50.0% |   7.1% |  12.5% |
| **vampi headless (후)** |  15 | 14 |   1 |  0 | **93.3%** | **100.0%** | **96.6%** |
| juice-shop ingest (후)  |   1 |  1 |   0 | 31 | 100.0% |   3.1% |   6.1% |
| juice-shop static (전)  |  84 | 13 |  71 | 19 |  15.5% |  40.6% |  22.4% |
| juice-shop static (후)  |  85 | 14 |  71 | 18 |  16.5% |  43.8% |  23.9% |
| juice-shop headless (전)| 241 |  5 | 236 | 27 |   2.1% |  15.6% |   3.7% |
| juice-shop headless (후)| 242 |  6 | 236 | 26 |   2.5% |  18.8% |   4.4% |
| dvwa ingest (후)        |   0 |  0 |   0 | 25 |   0.0% |   0.0% |   0.0% |
| dvwa static (전/후)     |  60 | 21 |  39 |  4 |  35.0% |  84.0% |  49.4% |
| dvwa headless (전/후)   |  91 | 22 |  69 |  3 |  24.2% |  88.0% |  37.9% |

- **VAmPI 재현율 0% → 100%.** `/openapi.json` 한 파일이 정답셋 14개를 전부 준다. 링크가 없어
  크롤로는 손댈 수 없던 표면이 통째로 측정 범위에 들어왔다. `ingest` 프로파일은 **P·R·F1 모두 100%** 다.
  static 이 92.9% 인 것은 `GET /` 를 크롤이 중복 기록하며 GT 의 한 항목과 어긋나서다.
- **Juice Shop 은 명세가 없다.** 등록 1건은 `robots.txt` 의 `/ftp` 뿐이고, **오탐 0(P 100%)** 이다.
  static·headless 재현율이 40.6% → 43.8% / 15.6% → 18.8% 로 오른 것도 이 한 건 덕이다.
- **DVWA 는 명세도 robots.txt 도 없다.** 인제스트 0건, static·headless 는 **모든 칸이 전과 동일** =
  회귀 없음. 이 대상에서는 얻을 것도 잃을 것도 없다.
- **팽창률은 전 대상 1.00x 유지.** 명세 경로(`/users/v1/{username}`)와 크롤 경로(`/users/v1/alice`)가
  한 노드로 합쳐지므로 트리가 갈라지지 않는다(#24 의 흡수 메커니즘 재사용).

#### 없는 명세를 발견했다고 하지 않는다

Juice Shop 은 SPA catch-all 이라 **없는 경로에도 200 + `index.html`** 을 돌려준다. 인제스터는
후보 20건을 프로브해 **13건을 본문 검증으로 걸러냈고, 명세를 하나도 만들어내지 않았다**:

```
[ING ] localhost:3000  요청=20 등록=1 출처=[robots:/robots.txt] 걸러냄=13
```

상태코드만 봤다면 `/openapi.json`·`/swagger.json`·`/v3/api-docs`·`/graphql` 을 "발견"하고
HTML 을 파싱하려 들었을 것이다. DVWA 는 후보가 전부 404 라 걸러낼 것도 없었다(요청=18 등록=0 걸러냄=0).

#### 정답셋 변경 (이번 측정에서 발견된 누락 2건)

인제스터가 찾아냈으나 정답셋에 없어 오탐으로 계상되던 항목을 **실재 확인 후 정답셋에 반영**했다.
정답셋이 틀렸던 것이지 인제스터가 틀린 게 아니다.

| 항목 | 근거 | 정답셋 |
|---|---|---|
| `GET /me` (vampi) | `curl -o /dev/null -w '%{http_code}' http://localhost:5000/me` → **401**(인증 필요=실재). `openapi.json` 에도 선언됨 | 13 → 14 |
| `GET /ftp` (juice-shop) | `curl http://localhost:3000/ftp` → **11307 bytes**, `.bak`/`.json`/`.md` 노출. catch-all `index.html` 은 9393 bytes 로 크기가 다름 | 31 → 32 |

`/ftp` 는 백업 파일이 노출된 디렉터리 목록이라 진단 도구가 **반드시 찾아야 하는** 표면이다.
juice-shop 정답셋은 스스로 "실제 기동 버전에 맞춰 검증·확장할 것"이라 적고 있어 확장이 맞다.

#### 소스맵은 검증 대상이 없다

세 대상 모두 소스맵을 서빙하지 않는다. Juice Shop 번들 3종(`main.js`·`scripts.js`·`polyfills.js`)은
`sourceMappingURL` 주석이 제거돼 있고, `.map` 요청이 200 인 것은 catch-all 이다(본문이 `index.html`).

```
[ING ] localhost:3000 소스맵 없음 (번들에 sourceMappingURL 없고 .map 도 명세 아님)
```

따라서 **on/off 재현율 델타는 필연적으로 0** 이며, 실측으로 기록할 수치가 없다.
기능 자체는 단위 테스트로 고정했다(`TestIngestSourceMapByConvention` — 주석 없이 `<번들>.map`
관례 프로브로 찾아 `sourcesContent` 에서 API 경로를 추출). **소스맵을 서빙하는 대상 선정은 이월한다.**

**재현**

```bash
docker run -d --rm -p 5000:5000 erev0s/vampi:latest
docker run -d --rm -p 3000:3000 bkimminich/juice-shop
cd backend && BENCH_GT=../docs/recon-groundtruth/vampi.yaml go test ./internal/recon/bench -run ReconBench -count=1 -timeout 900s -v
```

**단위 테스트** (인제스터 8종 — SPA catch-all 거부·노드 통합 포함)

```bash
cd backend && go test ./internal/recon/ingest -v
```

### 라이브니스 검증 (#26) — 3개 대상 before/after

정규식 추출물·링크 추종 결과의 실재 여부를 프로브해 강등하는 검증을 붙인 효과.
**이 이슈의 판정 지표는 오탐율**이며, 동시에 **재현율이 떨어지지 않아야** 한다(강등 ≠ 삭제).

측정: 2026-08-18. before = `efc0b8c`(#25 머지 시점), after = 라이브니스 검증.
**정답셋 기준: juice-shop 34 · dvwa 25 · vampi 14.**

| 대상 · 프로파일 | disc | TP | FP  | FN |   P    |   R    |  F1   | **오탐율** |
|-----------------|------|----|-----|----|--------|--------|-------|-----------|
| juice-shop static (전)   |  85 | 16 |  69 | 18 |  18.8% |  47.1% | 26.9% |  81.2% |
| **juice-shop static (후)** |  44 | 16 |  **28** | 18 | **36.4%** | **47.1%** | **41.0%** | **63.6%** |
| juice-shop headless (전) | 244 |  7 | 237 | 27 |   2.9% |  20.6% |  5.0% |  97.1% |
| juice-shop headless (후) | 242 |  7 | 235 | 27 |   2.9% |  20.6% |  5.1% |  97.1% |
| dvwa static (전)         |  60 | 21 |  39 |  4 |  35.0% |  84.0% | 49.4% |  65.0% |
| **dvwa static (후)**     |  56 | 21 |  **35** |  4 | **37.5%** | **84.0%** | **51.9%** | **62.5%** |
| dvwa headless (전)       |  91 | 22 |  69 |  3 |  24.2% |  88.0% | 37.9% |  75.8% |
| **dvwa headless (후)**   |  80 | 22 |  **58** |  3 | **27.5%** | **88.0%** | **41.9%** | **72.5%** |
| vampi (전/후, 3프로파일) | 변화 없음 — 전부 `spec` 출처라 프로브 후보 0건 |||||||

- **juice-shop static 오탐 69 → 28 (−59%), 정밀도 18.8% → 36.4%(약 2배).**
  **재현율은 47.1% 그대로** — 강등 41건이 전부 오탐에서만 나왔다. TP 는 하나도 잃지 않았다.
- **dvwa 는 static·headless 둘 다 개선**되고 재현율(84.0% / 88.0%)이 유지됐다.
- **vampi 는 아무 변화가 없다.** 전부 명세(`spec`) 출처라 프로브가 **한 건도 나가지 않았다** —
  면제 등급이 의도대로 동작한다는 증거다.
- **세 대상 8개 프로파일 전부 재현율(TP)이 한 칸도 떨어지지 않았다.**

#### 두 서버 유형이 서로 다른 코드 경로를 탄다

| 대상 | baseline | 판정 근거 | 강등 |
|---|---|---|---|
| juice-shop | `200 text/html 9393B` | 본문 시그니처 비교 (soft-404) | 41건 |
| dvwa | `""` (없음) | 정직한 404 → 상태코드만 | static 4 · headless 11건 |

Juice Shop 은 SPA catch-all 이라 없는 경로에도 200 을 준다. baseline 을 잡아 본문 모양을
비교해야만 SPA 클라이언트 라우트를 갈라낼 수 있다. 반대로 DVWA 는 정직하게 404 를 주므로
baseline 자체를 잡지 않고(`baseline=""`) 상태코드로만 판정한다 — **두 경로 모두 실측으로 확인**.

```
[LIVE] 후보=84 프로브=86 강등=41 면제=1  baseline="localhost:3000 → 200 text/html 9393B"
[LIVE] 후보=56 프로브=58 강등=4  면제=2  baseline=""          (dvwa static)
[LIVE] 후보=26 프로브=28 강등=11 면제=62 baseline=""          (dvwa headless)
```

`면제=62`(dvwa headless)는 헤드리스가 캡처한 XHR 과 실제 방문 페이지가 그만큼 있었다는 뜻이다.
프로브는 후보 수 + baseline 2건만큼만 나간다.

#### juice-shop headless 는 이 하네스에서 측정되지 않는다

수치가 변하지 않은 이유는 검증이 **동작하지 않아서가 아니라 도달하지 못해서**다.
하네스는 프로파일마다 120s 타임아웃에 `crawler.Cancel` 을 호출하는데(`run.go:93-94`),
취소된 컨텍스트에서는 검증을 건너뛴다. 사용자가 "중단"을 눌렀는데 프로브를 수십 건 더 보내는 것은
중단이 아니므로 이 동작 자체는 옳다.

**DVWA headless 는 92s 로 완주해 검증이 돌았고 11건을 강등했다** — headless 배선이 동작한다는
증거다. juice-shop headless 를 측정하려면 하네스 프로파일 타임아웃을 늘려야 하며,
이는 #22 하네스의 몫이라 이 이슈에서는 건드리지 않았다.

#### 정답셋 확장 (이번 측정에서 확인된 누락 2건)

라이브니스 프로브가 "실재한다"고 판정한 경로 중 정답셋에 없어 오탐으로 계상되던 항목을
확인해 반영했다. juice-shop 31 → 32(#25 `/ftp`) → **34**.

| 항목 | 응답 | 판단 |
|---|---|---|
| `GET /api/Quantitys` | 200 `application/json` 7628B — 실제 재고 데이터 | 명백한 누락 |
| `GET /api/Recycles` | 200 `application/json` 76B — `{"data":{"err":"…not supported."}}` | 아래 참조 |

판정 기준은 **"앱이 처리하는 라우트인가"** 다. 정답셋에 이미 있는 `/api/Cards`·`/api/Addresss` 도
401 을 주고 `/api/Complaints` 는 HTML 오류를 준다 — 데이터를 주는지가 기준이 아니다.
SPA catch-all(`text/html` 9393B)과 구분되는 응답이면 라우트는 실재한다.

> ⚠️ `/api/Recycles` 는 **GET 을 앱이 명시적으로 거부한다**(POST 는 지원). 라우트 자체는 실재하고
> 공격면이라 포함했으나, method 단위로 엄격히 보면 뺄 근거도 있다. YAML 주석에 근거를 남겼다.

두 항목은 **before 빌드도 이미 발견하고 있었다**(static TP 14 → 16). 정답셋이 틀렸던 것이지
라이브니스가 만들어낸 이득이 아니다. 그래서 before/after 를 **둘 다 GT=34 로 다시 측정**했다.
추가분은 JSON 응답이라 baseline 과 구분되어 **강등되지 않고 살아남았다**(after 도 TP 16).

**재현**

```bash
docker run -d --rm -p 3000:3000 bkimminich/juice-shop
cd backend && BENCH_GT=../docs/recon-groundtruth/juice-shop.yaml go test ./internal/recon/bench -run ReconBench -count=1 -timeout 900s -v
```

**단위 테스트** (라이브니스 7종 — soft-404·면제·401/403·판정 포기 포함)

```bash
cd backend && go test ./internal/recon/liveness -v
```

### 능동 콘텐츠 발견 (#27) — Juice Shop

wordlist 를 직접 프로브해 unlinked 공격면을 찾는 `discover` 프로파일. **기본 static 크롤과의 차이가
곧 발견분**이다. 측정: 2026-08-18, `bkimminich/juice-shop:latest`. **정답셋 기준: juice-shop 38**
(#27 로 unlinked 4건 추가 — 아래 참조).

| profile | disc | TP | FP | FN |   P    |   R    |  F1   | 오탐율 |
|---------|------|----|----|----|--------|--------|-------|--------|
| static (기준선) |  44 | 16 | 28 | 22 | 36.4% | 42.1% | 39.0% | 63.6% |
| **discover**    |  50 | **21** | 29 | **17** | **42.0%** | **55.3%** | **47.7%** | 58.0% |

- **재현율 42.1% → 55.3%, 정밀도 36.4% → 42.0%, F1 39.0% → 47.7%** — 셋 다 올랐다.
  능동 발견이 unlinked 표면 5건을 새로 찾고(TP 16 → 21) 오탐은 1건만 늘었다.
- **wordlist 154항목 중 발견 7건**(로그): `/support/logs`·`/encryptionkeys`·`/.well-known/security.txt`·
  `/api-docs`·`/ftp`·`/metrics`·`/robots.txt`. 뒤 3개는 이미 정답셋에 있어 TP, 앞 4개가 신규다.
- **soft-404 오탐 0**: 프로브 156건 중 143건을 catch-all(200 text/html 9393B)로 걸러냈다.
  `/admin`·`/.git/config`·`/.env`·`/backup` 등 SPA 라우트는 한 건도 등록하지 않았다.
- **5xx 도 버린다**: Juice Shop 은 없는 API 베이스 경로에 `500 "Unexpected path: /api"` 를 주는데,
  이걸 등록하면 `/api`·`/api/v1`·`/api/v2`·`/rest` 4건이 오탐이 된다. 능동 발견은 5xx 를 등록하지 않는다
  (라이브니스(#26)는 반대로 5xx 를 살린다 — 리스크 방향이 반대다).

#### 정답셋 확장 (능동 발견이 찾은 unlinked 4건)

전부 실재 확인 후 반영했다. juice-shop 34 → 38.

| 항목 | 응답 | 성격 |
|---|---|---|
| `/support/logs` | 200 text/html 8891B | **디렉터리 목록 노출**(로그) |
| `/encryptionkeys` | 200 text/html 7951B | **디렉터리 목록 노출**(키) |
| `/.well-known/security.txt` | 200 text/plain 475B | 표준 보안 연락처 |
| `/api-docs` | 301 → `/api-docs/` (Swagger UI) | API 문서 노출 |

`/support/logs`·`/encryptionkeys` 는 백업·로그가 그대로 열린 디렉터리라 진단 도구가 반드시 찾아야
하는 표면이다. 링크·명세·트래픽 어디에도 안 걸려 **능동 발견 없이는 도달 불가**였다.

**재현**

```bash
docker run -d --rm -p 3000:3000 bkimminich/juice-shop
cd backend && BENCH_GT=../docs/recon-groundtruth/juice-shop.yaml go test ./internal/recon/bench -run ReconBench -count=1 -timeout 1200s -v
```

**단위 테스트** (discover 8종 — soft-404 오탐 0·옵트인·5xx·예산·스코프)

```bash
cd backend && go test ./internal/recon/discover -v
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
  — **VAmPI 달성**(0% → 100%). 다만 **명세를 공개하는 대상에 한한다**: juice-shop 은 robots.txt 만,
  dvwa 는 아무것도 없어 각각 +3.2%p / 0%p 였다. 명세 없는 대상의 재현율은 크롤·필터의 몫으로 남는다.
- **#5 라이브니스 후 → 정밀도 마무리**(죽은/가짜 엔드포인트 제거): `P ≥ 60%`
  — **부분 달성**(#26). juice-shop static 정밀도가 18.8% → 36.4% 로 약 2배가 됐지만 60% 에는
  못 미친다. 남은 오탐 28건은 **실재하는 응답을 주는 경로**라 라이브니스로는 더 못 걷어낸다.
  정적자산·SPA 라우트 필터가 남은 몫이다.
- **#27 능동 발견 후 → 재현율 보강**(unlinked 표면): `discover` 프로파일이 R 42.1% → 55.3% 로,
  정밀도도 36.4% → 42.0% 로 동반 상승. unlinked 공격면(로그·키 디렉터리)을 새로 찾았다.
- **최종: R ≥ 80% · P ≥ 60% · F1 ≥ 0.70 · 팽창률 ≤ 1.2x**
