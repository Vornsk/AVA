package classify

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"proxypoc/internal/endpoints"
	"proxypoc/internal/llm"
)

func reset() {
	cacheMu.Lock()
	cache = map[string]Result{}
	cacheMu.Unlock()
	llm.SetProvider(nil)
}

func has(ls []string, l string) bool {
	for _, x := range ls {
		if x == l {
			return true
		}
	}
	return false
}

// TestRuleLabels — ★ 완료기준: 20+ 대표 경로가 룰로 올바르게 라벨링된다.
func TestRuleLabels(t *testing.T) {
	cases := []struct {
		method string
		path   string
		keys   []string
		want   []string // 반드시 포함해야 할 라벨(부분집합)
		absent []string // 있으면 안 되는 라벨
	}{
		{"POST", "/login", nil, []string{Auth}, nil},
		{"POST", "/api/v1/auth/token", nil, []string{Auth, API}, nil},
		{"POST", "/users/v1/register", nil, []string{Auth}, nil},
		{"GET", "/logout", nil, []string{Auth}, nil},
		{"POST", "/checkout", []string{"amount", "card"}, []string{Payment}, nil},
		{"POST", "/api/orders", nil, []string{Payment, API}, nil},
		{"POST", "/billing/invoice", nil, []string{Payment}, nil},
		{"POST", "/wallet/transfer", nil, []string{Payment}, nil},
		{"POST", "/upload", []string{"file"}, []string{Upload}, nil},
		{"POST", "/api/import", nil, []string{Upload, API}, nil},
		{"POST", "/user/avatar", nil, []string{Upload, PII}, nil},
		{"GET", "/admin", nil, []string{Admin}, nil},
		{"GET", "/admin/users", nil, []string{Admin}, nil},
		{"GET", "/backoffice/console", nil, []string{Admin}, nil},
		{"GET", "/internal/metrics", nil, []string{Admin}, nil},
		{"GET", "/profile", nil, []string{PII}, nil},
		{"GET", "/account/settings", nil, []string{PII}, nil},
		{"GET", "/customer/kyc", nil, []string{PII}, nil},
		{"GET", "/search", []string{"q"}, []string{Search}, nil},
		{"GET", "/api/search", []string{"query"}, []string{Search, API}, nil},
		{"GET", "/autocomplete", nil, []string{Search}, nil},
		{"GET", "/assets/main.css", nil, []string{Static}, []string{Auth, Payment, PII}},
		{"GET", "/static/app.js", nil, []string{Static}, nil},
		{"GET", "/favicon.ico", nil, []string{Static}, nil},
		{"GET", "/api/v2/products", nil, []string{API}, []string{Auth, Payment}},
		{"GET", "/graphql", nil, []string{API}, nil},
		{"GET", "/about", nil, []string{Other}, []string{Auth, Payment, Admin, PII}},
		{"GET", "/pricing", nil, nil, []string{Auth, Admin}}, // 특정 라벨 없음(other 로 폴백)
	}
	if len(cases) < 20 {
		t.Fatalf("대표 경로가 %d개 — 완료기준 20+ 미달", len(cases))
	}
	for _, c := range cases {
		got := fallback(mustLabels(Input{Method: c.method, Path: c.path, ParamKeys: c.keys}))
		for _, w := range c.want {
			if !has(got, w) {
				t.Errorf("%s %s: %v 에 %q 없음", c.method, c.path, got, w)
			}
		}
		for _, a := range c.absent {
			if has(got, a) {
				t.Errorf("%s %s: %v 에 %q 가 잘못 붙음", c.method, c.path, got, a)
			}
		}
	}
}

func mustLabels(in Input) []string { ls, _ := ruleLabels(in); return ls }

// TestConfidentSkipsLLM — 룰이 의미 라벨을 잡으면 LLM 을 부르지 않는다(착수 합의 ④).
func TestConfidentSkipsLLM(t *testing.T) {
	reset()
	defer reset()
	stub := &countingProvider{labels: []string{"payment"}}
	llm.SetProvider(stub)

	res := Classify(context.Background(), Input{Method: "POST", Path: "/login", ParamKeys: nil})
	if res.From != "rule" {
		t.Errorf("확정 경로인데 From=%q (want rule)", res.From)
	}
	if stub.calls != 0 {
		t.Errorf("확정 경로에 LLM 을 %d회 불렀다 (want 0)", stub.calls)
	}
	if !has(res.Labels, Auth) {
		t.Errorf("labels=%v (auth 없음)", res.Labels)
	}
}

// TestAmbiguousUsesLLM — 룰이 의미 라벨을 못 잡고 프로바이더가 있으면 LLM 을 부른다.
func TestAmbiguousUsesLLM(t *testing.T) {
	reset()
	defer reset()
	stub := &countingProvider{labels: []string{"pii"}}
	llm.SetProvider(stub)

	// /records 는 룰 키워드에 안 걸린다 → 모호 → LLM.
	res := Classify(context.Background(), Input{Method: "GET", Path: "/records/detail"})
	if res.From != "llm" {
		t.Fatalf("모호 경로인데 From=%q (want llm)", res.From)
	}
	if stub.calls != 1 {
		t.Errorf("LLM 호출 %d회 (want 1)", stub.calls)
	}
	if !has(res.Labels, PII) {
		t.Errorf("LLM 라벨 미반영: %v", res.Labels)
	}
	// ★ 토큰 절감: 프롬프트에 값·응답이 없고 경로·키만.
	if strings.Contains(stub.lastUser, "value") || !strings.Contains(stub.lastUser, "/records/detail") {
		t.Errorf("프롬프트가 규칙 위반(값 포함/경로 누락): %q", stub.lastUser)
	}
}

// TestNoProviderRuleOnly — 프로바이더가 없으면 모호해도 룰 결과(other)로 확정, LLM 미호출.
func TestNoProviderRuleOnly(t *testing.T) {
	reset()
	defer reset()
	res := Classify(context.Background(), Input{Method: "GET", Path: "/records"})
	if res.From != "rule" {
		t.Errorf("프로바이더 없음인데 From=%q", res.From)
	}
	if !reflect.DeepEqual(res.Labels, []string{Other}) {
		t.Errorf("labels=%v (want [other])", res.Labels)
	}
}

// TestCache — 같은 시그니처는 두 번째부터 캐시로, LLM 을 다시 부르지 않는다.
func TestCache(t *testing.T) {
	reset()
	defer reset()
	stub := &countingProvider{labels: []string{"pii"}}
	llm.SetProvider(stub)

	in := Input{Method: "GET", Path: "/records/1", ParamKeys: []string{"id"}}
	in2 := Input{Method: "GET", Path: "/records/2", ParamKeys: []string{"id"}} // 정규화하면 같은 꼴
	_ = Classify(context.Background(), in)
	r2 := Classify(context.Background(), in2)
	if r2.From != "cache" {
		t.Errorf("같은 꼴 재분류가 From=%q (want cache)", r2.From)
	}
	if stub.calls != 1 {
		t.Errorf("LLM 호출 %d회 (want 1 — 캐시가 중복 제거)", stub.calls)
	}
}

// TestRunLabelsTree — Run 이 트리 대상에 라벨을 붙이고 SetLabels 로 조회된다(E5/E6 접근).
func TestRunLabelsTree(t *testing.T) {
	reset()
	defer reset()
	llm.SetProvider(llm.MockProvider{}) // 오프라인 기본 — 룰+목 LLM

	tr := endpoints.NewTree()
	tr.RecordFrom(endpoints.SrcTraffic, "http", "h.com", "POST", "/login", nil, false, "")
	tr.RecordFrom(endpoints.SrcTraffic, "http", "h.com", "GET", "/admin/users", nil, false, "")
	tr.RecordFrom(endpoints.SrcTraffic, "http", "h.com", "POST", "/checkout", []endpoints.Param{{Name: "amount", In: "body"}}, false, "")

	rep := Run(context.Background(), tr)
	if rep.Endpoints != 3 || rep.Labeled != 3 {
		t.Fatalf("리포트=%+v (want endpoints=3 labeled=3)", rep)
	}
	byPath := map[string][]string{}
	for _, tg := range tr.Targets() {
		byPath[tg.Path] = tg.Labels
	}
	if !has(byPath["/login"], Auth) {
		t.Errorf("/login 라벨=%v (auth 없음)", byPath["/login"])
	}
	if !has(byPath["/admin/users"], Admin) {
		t.Errorf("/admin/users 라벨=%v (admin 없음)", byPath["/admin/users"])
	}
	if !has(byPath["/checkout"], Payment) {
		t.Errorf("/checkout 라벨=%v (payment 없음)", byPath["/checkout"])
	}
}

// (라벨 저장/복원 왕복은 endpoints 패키지의 TestLabelsPersist 에서 검증 — 파일 트리는 그쪽에서만 만든다.)

// ── 테스트 도우미 ────────────────────────────────────────────────────

type countingProvider struct {
	labels   []string
	calls    int
	lastUser string
}

func (p *countingProvider) Name() string { return "stub" }
func (p *countingProvider) Complete(_ context.Context, _ string, user string) (string, error) {
	p.calls++
	p.lastUser = user
	return `{"labels":["` + strings.Join(p.labels, `","`) + `"]}`, nil
}
