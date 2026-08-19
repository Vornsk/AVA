package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/scope"
)

// spaCatchAll — Juice Shop 처럼 없는 경로에도 index.html 을 200 으로 돌려주는 서버.
const spaIndex = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>SPA</title></head>
<body><script src="main.js"></script></body></html>`

const vampiSpec = `{
  "openapi": "3.0.1",
  "paths": {
    "/users/v1": {"get": {}},
    "/users/v1/_debug": {"get": {}},
    "/users/v1/register": {"post": {"requestBody": {"content": {"application/json": {"schema": {"type":"object","required":["username"],"properties":{"username":{"type":"string"},"password":{"type":"string"}}}}}}}},
    "/users/v1/{username}": {"get": {}, "delete": {}},
    "/books/v1": {"get": {"parameters": [{"name":"limit","in":"query","schema":{"type":"integer"}}]}}
  }
}`

// setup — 대상 서버를 스코프에 넣고 전역 트리를 비운다.
func setup(t *testing.T, srv *httptest.Server) *url.URL {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoints.Reset()
	scope.Configure([]string{u.Hostname()}, nil, nil)
	t.Cleanup(func() { scope.Configure(nil, nil, nil); endpoints.Reset() })
	return u
}

func discovered() map[string]bool {
	out := map[string]bool{}
	for _, tg := range endpoints.Targets() {
		for _, m := range tg.Methods {
			out[m+" "+tg.Path] = true
		}
	}
	return out
}

// TestIngestOpenAPI — OpenAPI 명세에서 경로·메서드·파라미터를 정확히 가져온다.
func TestIngestOpenAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(vampiSpec))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setup(t, srv)

	rep := Run(context.Background(), srv.URL, srv.Client())
	if rep.Recorded == 0 {
		t.Fatalf("등록 0건: %+v", rep)
	}
	got := discovered()
	for _, want := range []string{
		"GET /users/v1", "GET /users/v1/_debug", "POST /users/v1/register",
		"GET /users/v1/{username}", "DELETE /users/v1/{username}", "GET /books/v1",
	} {
		if !got[want] {
			t.Errorf("%s 미등록\n등록됨=%v", want, keys(got))
		}
	}
	if !hasSource(rep.Sources, "openapi:/openapi.json") {
		t.Errorf("출처 기록 없음: %v", rep.Sources)
	}

	// 파라미터: query 타입과 requestBody required 가 반영된다.
	books, ok := endpoints.Find(hostOf(srv), "/books/v1")
	if !ok {
		t.Fatal("/books/v1 없음")
	}
	if len(books.Params) != 1 || books.Params[0].Name != "limit" || books.Params[0].Type != "int" {
		t.Errorf("query 파라미터 반영 실패: %+v", books.Params)
	}
	reg, _ := endpoints.Find(hostOf(srv), "/users/v1/register")
	var username *endpoints.Param
	for i := range reg.Params {
		if reg.Params[i].Name == "username" {
			username = &reg.Params[i]
		}
	}
	if username == nil || !username.Required {
		t.Errorf("requestBody required 반영 실패: %+v", reg.Params)
	}
}

// TestIngestTagsSourceSpec — 인제스트 엔드포인트가 source=spec 으로 태깅된다 (이슈 #25 완료기준).
func TestIngestTagsSourceSpec(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(vampiSpec))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	setup(t, srv)
	Run(context.Background(), srv.URL, srv.Client())

	n := 0
	for _, tg := range endpoints.Targets() {
		if tg.Source != "spec" {
			t.Errorf("%s 출처 = %q, want spec", tg.Path, tg.Source)
		}
		n++
	}
	if n == 0 {
		t.Fatal("대상 0건")
	}
}

// TestIngestRejectsSPACatchAll — ★ 완료기준: 없는 명세를 발견했다고 하지 않는다.
// SPA 는 /openapi.json·/swagger.json·/graphql·*.map 전부에 200 + index.html 을 준다.
func TestIngestRejectsSPACatchAll(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte(spaIndex))
	}))
	defer srv.Close()
	setup(t, srv)

	rep := Run(context.Background(), srv.URL, srv.Client())
	if rep.Recorded != 0 {
		t.Errorf("SPA catch-all 에서 %d건을 등록했다 (want 0)\n출처=%v", rep.Recorded, rep.Sources)
	}
	if len(rep.Sources) != 0 {
		t.Errorf("없는 명세를 발견했다고 보고: %v", rep.Sources)
	}
	if len(rep.Rejected) == 0 {
		t.Error("걸러낸 후보가 기록되지 않았다 — 검증이 동작했는지 알 수 없다")
	}
	if hits == 0 {
		t.Error("프로브를 아예 보내지 않았다")
	}
}

// TestIngestRejectsJSONWithoutVersion — paths 는 있지만 OpenAPI 버전 표식이 없으면 명세가 아니다.
func TestIngestRejectsJSONWithoutVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"paths":{"/a":{"get":{}}}}`))
	}))
	defer srv.Close()
	setup(t, srv)

	rep := Run(context.Background(), srv.URL, srv.Client())
	if rep.Recorded != 0 {
		t.Errorf("버전 표식 없는 JSON 을 명세로 받아들였다: %d건", rep.Recorded)
	}
}

// TestIngestScopeHard — 스코프 밖 호스트로는 아무 요청도 나가지 않는다 (FR-2.1).
func TestIngestScopeHard(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(vampiSpec))
	}))
	defer srv.Close()

	endpoints.Reset()
	scope.Configure([]string{"other.example"}, nil, nil) // 대상 호스트를 넣지 않는다
	defer func() { scope.Configure(nil, nil, nil); endpoints.Reset() }()

	rep := Run(context.Background(), srv.URL, srv.Client())
	if hits != 0 {
		t.Errorf("스코프 밖으로 %d건 요청이 나갔다", hits)
	}
	if rep.Recorded != 0 {
		t.Errorf("스코프 밖 엔드포인트를 %d건 등록했다", rep.Recorded)
	}
}

// TestIngestRobotsAndSitemap — robots.txt 경로와 sitemap <loc> 를 시드로 등록한다.
func TestIngestRobotsAndSitemap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin/panel\nDisallow: /*.json$\nAllow: /public\nSitemap: /sitemap.xml\n"))
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0"?><urlset><url><loc>/docs/guide</loc></url><url><loc>/pricing</loc></url></urlset>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setup(t, srv)

	Run(context.Background(), srv.URL, srv.Client())
	got := discovered()
	for _, want := range []string{"GET /admin/panel", "GET /public", "GET /docs/guide", "GET /pricing"} {
		if !got[want] {
			t.Errorf("%s 미등록\n등록됨=%v", want, keys(got))
		}
	}
	// 와일드카드 규칙은 경로가 아니다.
	for k := range got {
		if strings.Contains(k, "*") {
			t.Errorf("와일드카드를 경로로 등록: %s", k)
		}
	}
}

// TestIngestSourceMapByConvention — 번들에 sourceMappingURL 이 없어도 <bundle>.map 관례로 찾는다.
// (Juice Shop 번들은 해당 주석이 제거돼 있다.)
func TestIngestSourceMapByConvention(t *testing.T) {
	const smap = `{"version":3,"sources":["app.ts"],"sourcesContent":["fetch('/api/orders'); fetch('/rest/wallet/balance');"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(spaIndex))
		case "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("console.log(1)")) // sourceMappingURL 주석 없음
		case "/main.js.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(smap))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setup(t, srv)

	rep := Run(context.Background(), srv.URL, srv.Client())
	got := discovered()
	for _, want := range []string{"GET /api/orders", "GET /rest/wallet/balance"} {
		if !got[want] {
			t.Errorf("소스맵에서 %s 미추출\n등록됨=%v\n출처=%v", want, keys(got), rep.Sources)
		}
	}
}

// TestIngestSourceMapFrameworkRoutes — ★ 이슈 #39 완료기준: 소스맵 원본에서 프레임워크
// 라우트를 복원하고 static-regex 로 태깅한다(라이브니스 검증 대상).
func TestIngestSourceMapFrameworkRoutes(t *testing.T) {
	// Angular 라우팅 모듈 + 벤더 파일. 벤더의 path: 는 뽑히면 안 된다.
	const smap = `{"version":3,` +
		`"sources":["webpack:///./src/app/app-routing.module.ts","webpack:///./node_modules/@angular/router/router.mjs"],` +
		`"sourcesContent":[` +
		`"const routes=[{path:'',component:H},{path:'administration',component:A},{path:'score-board',component:S},{path:'product/:id',component:P}];this.http.get('/rest/products/search');",` +
		`"const x={path:'vendor-internal',outlet:'y'};"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(spaIndex))
		case "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("console.log(1)"))
		case "/main.js.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(smap))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setup(t, srv)

	Run(context.Background(), srv.URL, srv.Client())
	got := discovered()
	for _, want := range []string{
		"GET /administration", "GET /score-board", "GET /product/{id}", "GET /rest/products/search",
	} {
		if !got[want] {
			t.Errorf("소스맵에서 %s 미복원\n등록됨=%v", want, keys(got))
		}
	}
	// 빈 path(인덱스 라우트)와 벤더 path: 는 등록하지 않는다.
	for _, bad := range []string{"GET /", "GET /vendor-internal"} {
		if got[bad] {
			t.Errorf("%s 를 등록했다 (오탐)", bad)
		}
	}
	// ★ 소스맵 추출물은 static-regex — 라이브니스 프로브 대상이어야 한다.
	tg, ok := endpoints.Find(hostOf(srv), "/administration")
	if !ok {
		t.Fatal("/administration 노드 없음")
	}
	if tg.Source != endpoints.SrcStaticRegex {
		t.Errorf("소스맵 추출물 출처 = %q, want %q (라이브니스 검증 대상)", tg.Source, endpoints.SrcStaticRegex)
	}
}

// TestIngestSourceMapLazyChunks — ★ 이슈 #39: 진입 번들이 참조하는 지연 로딩 청크의
// 소스맵까지 따라가 라우트를 복원한다. /administration 은 오직 지연 청크에만 있다.
func TestIngestSourceMapLazyChunks(t *testing.T) {
	// main.js 는 lazy 청크 admin.module.js 를 문자열로 참조한다(sourceMappingURL·main.js.map 없음).
	const adminMap = `{"version":3,"sources":["webpack:///./src/app/admin/admin-routing.module.ts"],` +
		`"sourcesContent":["const routes=[{path:'administration',children:[{path:'users',component:U}]}];"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(spaIndex))
		case "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			// webpack 런타임이 lazy 청크를 문자열로 참조하는 형태.
			_, _ = w.Write([]byte(`__webpack_require__.e("admin"); var c="admin.module.js";`))
		case "/admin.module.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("console.log('admin chunk')"))
		case "/admin.module.js.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(adminMap))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	setup(t, srv)

	Run(context.Background(), srv.URL, srv.Client())
	got := discovered()
	for _, want := range []string{"GET /administration", "GET /administration/users"} {
		if !got[want] {
			t.Errorf("지연 청크의 %s 미복원\n등록됨=%v", want, keys(got))
		}
	}
}

// TestIngestSpecThenCrawlSingleNode — ★ 완료기준: 명세 경로와 크롤 경로가 한 노드로 합쳐진다.
func TestIngestSpecThenCrawlSingleNode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(vampiSpec))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	u := setup(t, srv)
	Run(context.Background(), srv.URL, srv.Client())

	// 인제스트 뒤 크롤이 구체값을 만난다.
	endpoints.Record(u.Scheme, u.Host, "GET", "/users/v1/alice", nil, false, "")
	endpoints.Record(u.Scheme, u.Host, "GET", "/users/v1/_debug", nil, false, "")

	n := 0
	for _, tg := range endpoints.Targets() {
		if strings.HasPrefix(tg.Path, "/users/v1/") || tg.Path == "/users/v1/alice" {
			n++
		}
	}
	// /users/v1 밑: _debug · register · {username} 셋뿐이어야 한다(alice 는 {username} 으로 흡수).
	if n != 3 {
		t.Errorf("/users/v1 하위 대상 %d개 (want 3) — 명세 경로와 크롤 경로가 갈라졌다\n%v", n, keys(discovered()))
	}
	if _, ok := endpoints.Find(hostOf(srv), "/users/v1/{username}"); !ok {
		t.Error("{username} 노드 없음")
	}
}

func hostOf(srv *httptest.Server) string {
	u, _ := url.Parse(srv.URL)
	return u.Host
}

func hasSource(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
