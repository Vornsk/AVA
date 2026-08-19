package ingest

import (
	"reflect"
	"sort"
	"testing"
)

// TestCleanRoute — 프레임워크 라우트 값 정규화 (이슈 #39).
func TestCleanRoute(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/users", "/users", true},
		{"users", "/users", true},          // Angular 자식 라우트는 상대 경로
		{"score-board", "/score-board", true},
		{":id", "/{id}", true},             // React/Vue/Angular 파라미터
		{"users/:userId/edit", "/users/{userId}/edit", true},
		{"list/:id?", "/list/{id}", true},  // optional 파라미터
		{"product/:id/**", "/product/{id}", true}, // 와일드카드 자리에서 멈춘다
		{"", "", false},                    // 인덱스 라우트(빈 path)
		{"/", "", false},                   // 루트만
		{"*", "", false},
		{"**", "", false},
		{"https://cdn.example.com/a", "", false}, // 외부 URL
		{"//cdn/a", "", false},                   // 프로토콜 상대
		{"${base}/x", "", false},                 // 템플릿 보간
		{"a/${id}", "", false},                   // 보간 세그먼트
		{"a b", "", false},                       // 공백 = 경로 아님
	}
	for _, c := range cases {
		got, ok := cleanRoute(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("cleanRoute(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestIsVendorSource — node_modules·번들러 런타임은 라우트 추출에서 제외한다.
func TestIsVendorSource(t *testing.T) {
	vendor := []string{
		"webpack:///./node_modules/@angular/router/router.mjs",
		"webpack:///webpack/bootstrap",
		"webpack:///./vendor/lib.js",
	}
	app := []string{
		"webpack:///./src/app/app-routing.module.ts",
		"webpack:///./src/app/pages/login/login.component.ts",
	}
	for _, p := range vendor {
		if !isVendorSource(p) {
			t.Errorf("%q 를 앱 소스로 봤다 (벤더여야 한다)", p)
		}
	}
	for _, p := range app {
		if isVendorSource(p) {
			t.Errorf("%q 를 벤더로 봤다 (앱 소스여야 한다)", p)
		}
	}
}

// TestExtractFromSources — ★ 완료기준: 파일 단위로 프레임워크 라우트·API 경로를 뽑고
// 벤더 파일의 path: 는 제외한다.
func TestExtractFromSources(t *testing.T) {
	files := []SourceFile{
		{ // Angular 라우팅 모듈
			Path:    "webpack:///./src/app/app-routing.module.ts",
			Content: "const routes=[{path:'',component:H},{path:'administration',component:A},{path:'score-board',component:S},{path:'product/:id',component:P}];",
		},
		{ // Vue 라우터
			Path:    "webpack:///./src/router/index.ts",
			Content: "export default [{ path: '/about', component: About }, { path: '/cart', component: Cart }]",
		},
		{ // React Router (JSX)
			Path:    "webpack:///./src/App.tsx",
			Content: `<Routes><Route path="/login" element={<Login/>} /><Route path="/dashboard" element={<Dash/>} /></Routes>`,
		},
		{ // API 호출 — 프리픽스 앵커
			Path:    "webpack:///./src/app/services/api.service.ts",
			Content: "this.http.get('/rest/products/search'); this.http.post('/api/v1/orders');",
		},
		{ // 벤더 — path: 가 있어도 뽑으면 안 된다
			Path:    "webpack:///./node_modules/@angular/router/router.mjs",
			Content: "const x={path:'vendor-internal-route',outlet:'x'};",
		},
		{Path: "webpack:///./src/empty.ts", Content: ""}, // 본문 없음 — 건너뛴다
	}

	got := extractFromSources(files)
	sort.Strings(got)

	want := []string{
		"/about", "/administration", "/api/v1/orders", "/cart",
		"/dashboard", "/login", "/product/{id}", "/rest/products/search",
		"/score-board",
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("추출 결과 불일치\n got=%v\nwant=%v", got, want)
	}
	for _, bad := range got {
		if bad == "/vendor-internal-route" {
			t.Error("벤더 파일의 path: 를 라우트로 등록했다")
		}
		if bad == "/" {
			t.Error("빈 path(인덱스 라우트)를 / 로 등록했다")
		}
	}
}

// TestParseSourceMapPairs — sources 와 sourcesContent 를 인덱스로 짝짓는다.
// sourcesContent 가 짧으면 나머지 파일은 본문이 빈 채로 경로만 남는다.
func TestParseSourceMapPairs(t *testing.T) {
	const smap = `{"version":3,"sources":["a.ts","b.ts","c.ts"],"sourcesContent":["AAA","BBB"]}`
	files, err := parseSourceMap(smap, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("파일 %d개 (want 3)", len(files))
	}
	if files[0].Path != "a.ts" || files[0].Content != "AAA" {
		t.Errorf("files[0] = %+v", files[0])
	}
	if files[2].Path != "c.ts" || files[2].Content != "" {
		t.Errorf("본문 없는 파일이 짝을 잘못 잡았다: %+v", files[2])
	}
}

// TestParseSourceMapRejectsNonMap — 소스맵이 아니면 거부한다(SPA HTML·비JSON·version 0).
func TestParseSourceMapRejectsNonMap(t *testing.T) {
	for _, body := range []string{
		"<!DOCTYPE html><html></html>",
		"not json at all",
		`{"sources":["a.ts"]}`,                      // version 없음
		`{"version":3,"sources":[]}`,                // sources 비어 있음
	} {
		if _, err := parseSourceMap(body, "application/json"); err == nil {
			t.Errorf("소스맵이 아닌데 통과: %q", body)
		}
	}
}
