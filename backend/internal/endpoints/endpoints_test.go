package endpoints

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// 영속화 왕복: dump 후 새 트리로 Load 하면 스캔 대상(scheme·host·auth·params·verdict)이 그대로 복원.
func TestTreePersistence(t *testing.T) {
	const fn = "test_ep.json"
	defer os.Remove(fn)
	tr := &Tree{roots: map[string]*node{}, name: fn}
	tr.Record("http", "h.com:8888", "GET", "/item", []Param{{Name: "id", In: "query", Sample: "1"}}, true, "룰 허용")
	tr.Record("http", "h.com:8888", "POST", "/transfer", []Param{{Name: "amt", In: "body"}}, true, "")

	tr2 := &Tree{roots: map[string]*node{}, name: fn}
	tr2.Load()
	var item *Target
	for _, g := range tr2.Targets() {
		if g.Path == "/item" {
			g := g
			item = &g
		}
	}
	if item == nil {
		t.Fatal("/item 복원 안 됨")
	}
	if item.Scheme != "http" || item.Host != "h.com:8888" || !item.Auth {
		t.Errorf("대상 충실도 손실: %+v", *item)
	}
	if len(item.Params) != 1 || item.Params[0].Name != "id" || item.Params[0].Sample != "1" {
		t.Errorf("파라미터 손실: %+v", item.Params)
	}
	if item.Verdict != "룰 허용" {
		t.Errorf("verdict 손실: %q", item.Verdict)
	}
}

func reset() {
	def.mu.Lock()
	def.roots = map[string]*node{}
	def.mu.Unlock()
}

func TestNormalizePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/user/42", "/user/{id}"},
		{"/user/43", "/user/{id}"}, // 42·43 → 동일 (dedup)
		{"/user/42/orders/7", "/user/{id}/orders/{id}"},
		{"/get", "/get"},
		{"/v2/items", "/v2/items"}, // v2는 숫자만 아님 → 유지
	}
	for _, c := range cases {
		if got := NormalizePath(c.in); got != c.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if NormalizePath("/user/42") != NormalizePath("/user/43") {
		t.Error("numeric-id paths must normalize equal (LLM cache dedup)")
	}
}

func TestExtractParamsAndBodyRestore(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://x/y?a=1&b=2", strings.NewReader("c=3&d=4"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ps := ExtractParams(req)
	loc := map[string]string{}
	for _, p := range ps {
		loc[p.Name] = p.In
	}
	if loc["a"] != "query" || loc["b"] != "query" {
		t.Errorf("query params wrong: %v", loc)
	}
	if loc["c"] != "body" || loc["d"] != "body" {
		t.Errorf("body params wrong: %v", loc)
	}

	// 본문이 복원돼야 대상 전송에 지장 없음
	body, _ := io.ReadAll(req.Body)
	if string(body) != "c=3&d=4" {
		t.Errorf("body not restored: %q", body)
	}
}

// TestExtractJSONBody — application/json 스칼라 leaf 를 dot-path(중첩·배열 포함) In="json" 으로 캡처하고 본문 복원.
func TestExtractJSONBody(t *testing.T) {
	raw := `{"user":"alice","age":30,"nested":{"x":1},"items":[{"name":"a"},{"name":"b"}]}`
	req, _ := http.NewRequest("POST", "http://x/api?p=1", strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")

	loc := map[string]string{}
	for _, p := range ExtractParams(req) {
		loc[p.Name] = p.In
	}
	if loc["p"] != "query" {
		t.Errorf("query p wrong: %v", loc)
	}
	if loc["user"] != "json" || loc["age"] != "json" {
		t.Errorf("top-level json keys wrong: %v", loc)
	}
	if loc["nested.x"] != "json" { // 중첩 객체 leaf
		t.Errorf("중첩 객체 leaf 미캡처: %v", loc)
	}
	if loc["items.0.name"] != "json" || loc["items.1.name"] != "json" { // 배열 요소 leaf
		t.Errorf("배열 요소 leaf 미캡처: %v", loc)
	}
	// 본문 복원 확인.
	body, _ := io.ReadAll(req.Body)
	if string(body) != raw {
		t.Errorf("json body not restored: %q", body)
	}
}

func TestTargetInteresting(t *testing.T) {
	if (Target{Host: "a", Path: "/"}).Interesting() {
		t.Error("plain target (no params/auth/verdict) should not be interesting")
	}
	if !(Target{Params: []Param{{Name: "id"}}}).Interesting() {
		t.Error("target with params → interesting")
	}
	if !(Target{Auth: true}).Interesting() {
		t.Error("auth-required target → interesting")
	}
	if !(Target{Verdict: "LLM 허용"}).Interesting() {
		t.Error("risk-judged target → interesting")
	}
}

func TestParamTypesSampleCookie(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://x/y?id=42&email=a@b.com&ok=true&password=secret", nil)
	req.Header.Set("Cookie", "session=abc123")

	got := map[string]Param{}
	for _, p := range ExtractParams(req) {
		got[p.Name] = p
	}
	if got["id"].Type != "int" {
		t.Errorf("id type = %q, want int", got["id"].Type)
	}
	if got["email"].Type != "email" {
		t.Errorf("email type = %q, want email", got["email"].Type)
	}
	if got["ok"].Type != "bool" {
		t.Errorf("ok type = %q, want bool", got["ok"].Type)
	}
	if got["password"].Sample != "***" {
		t.Errorf("password sample = %q, want *** (masked)", got["password"].Sample)
	}
	if got["id"].Sample != "42" {
		t.Errorf("id sample = %q, want 42 (non-sensitive)", got["id"].Sample)
	}
	if got["session"].In != "cookie" {
		t.Errorf("session location = %q, want cookie", got["session"].In)
	}
}

func TestParamRequired(t *testing.T) {
	reset()
	// /r 에 두 번 요청: a는 매번, b는 한 번만 → a required, b optional
	Record("https", "h.com", "GET", "/r", []Param{{Name: "a", In: "query"}}, false, "")
	Record("https", "h.com", "GET", "/r", []Param{{Name: "a", In: "query"}, {Name: "b", In: "query"}}, false, "")
	n, _ := Find("h.com", "/r")
	req := map[string]bool{}
	for _, p := range n.Params {
		req[p.Name] = p.Required
	}
	if !req["a"] {
		t.Error("a should be required (in all 2 requests)")
	}
	if req["b"] {
		t.Error("b should be optional (in 1 of 2 requests)")
	}
}

func TestTreeDedupAndFind(t *testing.T) {
	reset()
	Record("https", "h.com", "GET", "/user/42", nil, false, "")
	Record("https", "h.com", "GET", "/user/43", nil, false, "")

	n, ok := Find("h.com", "/user/{id}")
	if !ok {
		t.Fatal("normalized node /user/{id} not found")
	}
	if n.Count != 2 {
		t.Errorf("dedup count = %d, want 2 (42+43 → {id})", n.Count)
	}
	if len(n.Methods) != 1 || n.Methods[0] != "GET" {
		t.Errorf("methods = %v", n.Methods)
	}
}

func TestNodeFields(t *testing.T) {
	reset()
	Record("https", "h.com", "POST", "/pay", []Param{{Name: "amt", In: "body"}}, true, "LLM 허용")
	n, ok := Find("h.com", "/pay")
	if !ok {
		t.Fatal("node not found")
	}
	if !n.Auth {
		t.Error("auth_required should be true")
	}
	if n.Verdict != "LLM 허용" {
		t.Errorf("verdict = %q", n.Verdict)
	}
	if len(n.Params) != 1 || n.Params[0].In != "body" {
		t.Errorf("params = %v", n.Params)
	}
}

func TestSummary(t *testing.T) {
	reset()
	Record("https", "h.com", "GET", "/a", nil, false, "")
	Record("https", "h.com", "GET", "/b/1", nil, false, "")
	Record("https", "h.com", "GET", "/b/2", nil, false, "")
	s := Summary()
	// endpoints with methods: /a, /b/{id}  (structural /b has no methods)
	if s.Endpoints != 2 {
		t.Errorf("endpoints = %d, want 2", s.Endpoints)
	}
	if s.Hosts != 1 {
		t.Errorf("hosts = %d, want 1", s.Hosts)
	}
	if s.Hits != 3 {
		t.Errorf("hits = %d, want 3", s.Hits)
	}
}
