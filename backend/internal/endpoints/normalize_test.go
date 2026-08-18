package endpoints

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// TestNormalizePathV2 — 대표 경로 → 기대 템플릿 매핑 (이슈 #24 완료기준 1).
//
//	재현: go test ./internal/endpoints -run Normalize -v
func TestNormalizePathV2(t *testing.T) {
	cases := []struct{ in, want, why string }{
		// ── 숫자 (v1 하위호환) ──
		{"/user/42", "/user/{id}", "숫자-only → {id} (v1 동작 유지)"},
		{"/user/42/orders/7", "/user/{id}/orders/{id}", "복수 숫자 세그먼트"},
		{"/api/Products/0", "/api/Products/{id}", "0 도 숫자"},
		// ── UUID ──
		{"/u/550e8400-e29b-41d4-a716-446655440000", "/u/{uuid}", "표준 UUID"},
		{"/rest/basket/6BA7B810-9DAD-11D1-80B4-00C04FD430C8", "/rest/basket/{uuid}", "대문자 UUID"},
		{"/u/550e8400-e29b-41d4-a716-446655440000/avatar", "/u/{uuid}/avatar", "UUID 뒤 정적 세그먼트 보존"},
		// ── hex / hash ──
		{"/t/0123456789abcdef0123", "/t/{hash}", "hex 20자 → {hash}"},
		{"/t/0123456789abcdef", "/t/{hash}", "hex 16자 (경계, 포함)"},
		{"/t/0123456789abcde", "/t/0123456789abcde", "hex 15자 (경계, 미포함)"},
		{"/x/cafe", "/x/cafe", "짧은 hex 는 실단어일 수 있어 보존"},
		{"/u/550e8400e29b41d4a716446655440000", "/u/{hash}", "dash 없는 32자 UUID 는 hex 로"},
		// ── 날짜 ──
		{"/logs/2026-08-18", "/logs/{date}", "ISO 날짜"},
		{"/logs/2026/08/18", "/logs/{id}/{id}/{id}", "슬래시 분할 날짜는 각각 숫자"},
		{"/posts/2026-08-18/comments", "/posts/{date}/comments", "날짜 뒤 정적 세그먼트 보존"},
		// ── base64-ish ──
		{"/dl/aGVsbG8gd29ybGQgZm9vYmFy1A==", "/dl/{b64}", "base64 (숫자+대문자+패딩)"},
		{"/t/eyJhbGciOiJIUzI1NiJ9", "/t/{b64}", "base64url (JWT 헤더)"},
		{"/rest/admin/application-configuration", "/rest/admin/application-configuration", "소문자 slug 은 b64 아님 (숫자·대문자 없음)"},
		{"/rest/user/reset-password", "/rest/user/reset-password", "짧은 slug 보존"},
		// ── 확장자 / 번들 해시 ──
		{"/assets/main.9f8a7b6c5d4e3f21.js", "/assets/main.{hash}.js", "웹팩 번들 해시만 접고 확장자 보존"},
		{"/report/2026-08-18.csv", "/report/{date}.csv", "확장자 보존"},
		{"/index.html", "/index.html", "정적 파일명 보존"},
		{"/v/1.2.3/app.js", "/v/{id}.{id}.{id}/app.js", "버전 세그먼트 — 숫자만 있으면 확장자 아님"},
		{"/a/config.v2.json", "/a/config.v2.json", "영문 시작 조각은 값이 아님"},
		// ── 접지 말아야 할 것 ──
		{"/get", "/get", "짧은 라우트명"},
		{"/v2/items", "/v2/items", "v2 는 숫자-only 아님"},
		{"/rest/products/search", "/rest/products/search", "실제 엔드포인트"},
		{"/api/Feedbacks", "/api/Feedbacks", "대소문자 보존"},
		{"/", "/", "루트"},
		{"", "", "빈 경로"},
		{"/user/{id}", "/user/{id}", "이미 템플릿이면 그대로 (재정규화 멱등)"},
		{"/user/{slug}/x", "/user/{slug}/x", "{slug} 도 보존"},
	}
	if len(cases) < 20 {
		t.Fatalf("완료기준: 대표 경로 20종 이상 필요, 현재 %d종", len(cases))
	}
	for _, c := range cases {
		if got := NormalizePath(c.in); got != c.want {
			t.Errorf("NormalizePath(%q) = %q, want %q  (%s)", c.in, got, c.want, c.why)
		}
	}
}

// TestNormalizeIdempotent — 정규화 결과를 다시 정규화해도 같아야 한다(로드 마이그레이션 안전성).
func TestNormalizeIdempotent(t *testing.T) {
	for _, p := range []string{
		"/user/42", "/u/550e8400-e29b-41d4-a716-446655440000", "/logs/2026-08-18",
		"/assets/main.9f8a7b6c5d4e3f21.js", "/t/eyJhbGciOiJIUzI1NiJ9", "/rest/products/search",
	} {
		once := NormalizePath(p)
		if twice := NormalizePath(once); twice != once {
			t.Errorf("멱등성 위반: %q → %q → %q", p, once, twice)
		}
	}
}

// TestNormalizeDedup — 같은 엔드포인트의 다른 값들이 하나로 접히는가 (LLM 캐시 dedup, FR-2.3).
func TestNormalizeDedup(t *testing.T) {
	groups := [][]string{
		{"/user/42", "/user/43"},
		{"/u/550e8400-e29b-41d4-a716-446655440000", "/u/6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		{"/logs/2026-08-18", "/logs/2025-01-01"},
		{"/t/0123456789abcdef0123", "/t/fedcba98765432100000"},
	}
	for _, g := range groups {
		first := NormalizePath(g[0])
		for _, p := range g[1:] {
			if NormalizePath(p) != first {
				t.Errorf("dedup 실패: %q(%s) ≠ %q(%s)", g[0], first, p, NormalizePath(p))
			}
		}
	}
}

// TestInferTypeContract — inferType 이 classifyToken 과 규칙을 공유하되 반환 집합은 v1 그대로.
// (Param.Type 은 저장·표시 계약이라 {hash}/{date}/{b64} 를 새 타입으로 흘리지 않는다.)
func TestInferTypeContract(t *testing.T) {
	cases := map[string]string{
		"":                                     "string",
		"42":                                   "int",
		"true":                                 "bool",
		"false":                                "bool",
		"550e8400-e29b-41d4-a716-446655440000": "uuid",
		"a@b.com":                              "email",
		"0123456789abcdef0123":                 "string", // hash 는 string 유지
		"2026-08-18":                           "string", // date 도 string 유지
		"hello":                                "string",
	}
	for in, want := range cases {
		if got := inferType(in); got != want {
			t.Errorf("inferType(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── 형제 다양성 클러스터링 ────────────────────────────────────────

// slugPath — 접기 테스트용 고유 경로 (i 마다 다른 값).
func slugPath(i int) string { return fmt.Sprintf("/blog/post-%02d-%s", i, "abcdefghijklmnop"[i:i+1]) }

// TestFoldSiblingsThreshold — 임계치 미만은 접지 않고, 넘으면 {slug} 하나로 접힌다.
func TestFoldSiblingsThreshold(t *testing.T) {
	tr := NewTree()
	for i := 0; i < slugMinSiblings-1; i++ {
		tr.Record("https", "h.com", "GET", slugPath(i), nil, false, "")
	}
	if n := childCount(tr, "h.com", "/blog"); n != slugMinSiblings-1 {
		t.Fatalf("임계치 미만인데 접힘: 자식 %d개 (want %d)", n, slugMinSiblings-1)
	}
	tr.Record("https", "h.com", "GET", slugPath(slugMinSiblings-1), nil, false, "") // 임계치 도달
	if n := childCount(tr, "h.com", "/blog"); n != 1 {
		t.Fatalf("임계치 도달했는데 안 접힘: 자식 %d개 (want 1)", n)
	}
	got, ok := tr.Find("h.com", "/blog/{slug}")
	if !ok {
		t.Fatal("{slug} 노드 없음")
	}
	if got.Count != slugMinSiblings {
		t.Errorf("병합 count = %d, want %d (히트 합산)", got.Count, slugMinSiblings)
	}
}

// TestFoldSiblingsAbsorb — 한 번 접힌 자리는 이후 값을 바로 흡수한다(재팽창 방지).
func TestFoldSiblingsAbsorb(t *testing.T) {
	tr := NewTree()
	for i := 0; i < slugMinSiblings; i++ {
		tr.Record("https", "h.com", "GET", slugPath(i), nil, false, "")
	}
	tr.Record("https", "h.com", "GET", "/blog/brand-new-article", nil, false, "")
	if n := childCount(tr, "h.com", "/blog"); n != 1 {
		t.Fatalf("접힌 자리가 재팽창: 자식 %d개", n)
	}
	got, _ := tr.Find("h.com", "/blog/{slug}")
	if got.Count != slugMinSiblings+1 {
		t.Errorf("흡수 후 count = %d, want %d", got.Count, slugMinSiblings+1)
	}
}

// TestFindResolvesSlugged — 접힌 자리는 구체 경로로도 조회된다.
// Record 는 {slug} 로 흡수하는데 Find 가 리터럴 세그먼트만 보면
// /api/endpoints/detail?path=<구체경로> 가 404 가 된다.
func TestFindResolvesSlugged(t *testing.T) {
	tr := NewTree()
	for i := 0; i < slugMinSiblings; i++ {
		tr.Record("https", "h.com", "GET", slugPath(i), nil, false, "")
	}
	if _, ok := tr.Find("h.com", "/blog/{slug}"); !ok {
		t.Fatal("템플릿 경로 조회 실패")
	}
	if _, ok := tr.Find("h.com", slugPath(0)); !ok {
		t.Errorf("접힌 구체 경로 %s 조회 실패", slugPath(0))
	}
	if _, ok := tr.Find("h.com", "/blog/never-seen-2-value"); !ok {
		t.Error("같은 자리의 새 값도 {slug} 로 해석돼야 함")
	}
	// 값처럼 생기지 않은 세그먼트는 흡수 대상이 아니므로 여전히 없음.
	if _, ok := tr.Find("h.com", "/blog/search"); ok {
		t.Error("라우트명이 {slug} 로 잘못 해석됨")
	}
}

// TestFoldSiblingsProtectsRoot — 호스트 루트 직속 자식은 절대 접히지 않는다.
// juice-shop /metrics 처럼 루트에 붙은 실제 엔드포인트가 사라지면 재현율이 무너진다.
func TestFoldSiblingsProtectsRoot(t *testing.T) {
	tr := NewTree()
	for i := 0; i < slugMinSiblings*2; i++ {
		tr.Record("https", "h.com", "GET", fmt.Sprintf("/route-%02d", i), nil, false, "")
	}
	tr.Record("https", "h.com", "GET", "/metrics", nil, false, "")
	if _, ok := tr.Find("h.com", "/metrics"); !ok {
		t.Error("루트 직속 /metrics 가 접혀 사라짐 — 재현율 회귀")
	}
	if _, ok := tr.Find("h.com", "/{slug}"); ok {
		t.Error("루트 직속 자식이 {slug} 로 접힘 (보수적 경계 위반)")
	}
}

// TestFoldSiblingsProtectsParams — 파라미터가 있는 노드(공격면)는 접기 대상이 아니다.
func TestFoldSiblingsProtectsParams(t *testing.T) {
	tr := NewTree()
	tr.Record("https", "h.com", "GET", "/blog/search", []Param{{Name: "q", In: "query"}}, false, "")
	for i := 0; i < slugMinSiblings; i++ {
		tr.Record("https", "h.com", "GET", slugPath(i), nil, false, "")
	}
	if _, ok := tr.Find("h.com", "/blog/search"); !ok {
		t.Error("파라미터 있는 /blog/search 가 접혀 사라짐 — 공격면 손실")
	}
}

// TestFoldSiblingsProtectsSubtree — 자식이 있는 노드(구조 라우트)는 접지 않는다.
func TestFoldSiblingsProtectsSubtree(t *testing.T) {
	tr := NewTree()
	tr.Record("https", "h.com", "GET", "/blog/archive/2026", nil, false, "")
	for i := 0; i < slugMinSiblings; i++ {
		tr.Record("https", "h.com", "GET", slugPath(i), nil, false, "")
	}
	if _, ok := tr.Find("h.com", "/blog/archive/{id}"); !ok {
		t.Error("하위 구조가 있는 /blog/archive 가 접혀 사라짐")
	}
}

// TestFoldSiblingsProtectsRestCollections — REST 리소스 컬렉션은 접히면 안 된다 (회귀).
// juice-shop /api 밑 12종 이상의 리소스가 {slug} 로 접혀 하네스 재현율이
// 41.9% → 22.6% 로 무너진 적이 있다(#24). looksLikeValue 가드의 회귀 테스트.
func TestFoldSiblingsProtectsRestCollections(t *testing.T) {
	tr := NewTree()
	res := []string{
		"Products", "Users", "Feedbacks", "Complaints", "Challenges", "BasketItems",
		"Quantitys", "Recycles", "Cards", "Addresss", "Deliverys", "SecurityQuestions",
		"SecurityAnswers", "PrivacyRequests",
	}
	if len(res) < slugMinSiblings {
		t.Fatalf("회귀 재현에 형제 %d개 이상 필요", slugMinSiblings)
	}
	for _, r := range res {
		tr.Record("https", "h.com", "GET", "/api/"+r, nil, false, "")
	}
	// 하이픈 하나짜리 라우트명도 값이 아니다.
	tr.Record("https", "h.com", "GET", "/rest/admin/application-configuration", nil, false, "")
	tr.Record("https", "h.com", "GET", "/rest/user/reset-password", nil, false, "")

	if n := childCount(tr, "h.com", "/api"); n != len(res) {
		t.Errorf("REST 리소스가 접힘: /api 자식 %d개 (want %d)", n, len(res))
	}
	for _, want := range []string{"/api/Products", "/api/Feedbacks", "/api/SecurityQuestions",
		"/rest/admin/application-configuration", "/rest/user/reset-password"} {
		if _, ok := tr.Find("h.com", want); !ok {
			t.Errorf("%s 가 사라짐 — 재현율 회귀", want)
		}
	}
}

// TestLooksLikeValue — 값 표식 판정 (라우트명 vs slug 값).
func TestLooksLikeValue(t *testing.T) {
	value := []string{"my-first-post", "red-nike-shoes-42", "order-2026-08-a", "Aashish683", "v1_beta_2", "post7"}
	route := []string{"Products", "SecurityQuestions", "application-configuration", "reset-password",
		"search", "whoami", "order-history", "login"}
	for _, s := range value {
		if !looksLikeValue(s) {
			t.Errorf("looksLikeValue(%q) = false, want true (값)", s)
		}
	}
	for _, s := range route {
		if looksLikeValue(s) {
			t.Errorf("looksLikeValue(%q) = true, want false (라우트명)", s)
		}
	}
}

// TestFoldSiblingsLowDiversity — 같은 값이 반복되면(고유비율 낮음) 라우트명이므로 접지 않는다.
func TestFoldSiblingsLowDiversity(t *testing.T) {
	tr := NewTree()
	for i := 0; i < slugMinSiblings; i++ {
		for r := 0; r < 5; r++ { // 각 경로를 5회씩 재방문 → 고유비율 12/60 = 0.2
			tr.Record("https", "h.com", "GET", slugPath(i), nil, false, "")
		}
	}
	if n := childCount(tr, "h.com", "/blog"); n != slugMinSiblings {
		t.Errorf("반복 방문되는 라우트명이 접힘: 자식 %d개 (want %d)", n, slugMinSiblings)
	}
}

// TestMergeRequiredIntegrity — 정규화로 병합된 뒤에도 Required(seen == count) 정합이 유지된다.
func TestMergeRequiredIntegrity(t *testing.T) {
	tr := NewTree()
	tr.Record("https", "h.com", "GET", "/a/1", []Param{{Name: "q", In: "query"}}, false, "")
	tr.Record("https", "h.com", "GET", "/a/2", []Param{{Name: "q", In: "query"}}, false, "")
	n, ok := tr.Find("h.com", "/a/{id}")
	if !ok {
		t.Fatal("/a/{id} 없음")
	}
	if n.Count != 2 {
		t.Fatalf("count = %d, want 2", n.Count)
	}
	if len(n.Params) != 1 || !n.Params[0].Required {
		t.Errorf("모든 요청에 있던 q 가 required 아님: %+v", n.Params)
	}
}

// ── 하위호환: v1 저장 파일 마이그레이션 ────────────────────────────

// TestLoadMigratesV1Tree — v1 로 저장된 endpoints.json 을 로드하면 v2 로 재분류·병합된다.
func TestLoadMigratesV1Tree(t *testing.T) {
	const fn = "test_migrate.json"
	defer os.Remove(fn)

	// v1 저장물: UUID 두 개가 각각 별도 노드로 남아 있다(v1 은 숫자만 접었다).
	v1 := []storeNode{{
		Segment: "h.com",
		Children: []storeNode{{
			Segment: "u", Path: "/u",
			Children: []storeNode{
				{
					Segment:  "550e8400-e29b-41d4-a716-446655440000",
					Path:     "/u/550e8400-e29b-41d4-a716-446655440000",
					LastPath: "/u/550e8400-e29b-41d4-a716-446655440000", Scheme: "https",
					Methods: []string{"GET"}, Count: 3, LastSeen: "2026-08-17T00:00:00Z",
					Params: []storeParam{{Name: "tab", Ins: []string{"query"}, Seen: 3}},
				},
				{
					Segment:  "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
					Path:     "/u/6ba7b810-9dad-11d1-80b4-00c04fd430c8",
					LastPath: "/u/6ba7b810-9dad-11d1-80b4-00c04fd430c8", Scheme: "https",
					Methods: []string{"POST"}, Count: 2, LastSeen: "2026-08-18T00:00:00Z",
					Params: []storeParam{{Name: "tab", Ins: []string{"query"}, Seen: 2}},
				},
			},
		}},
	}}
	data, _ := json.MarshalIndent(v1, "", "  ")
	if err := os.WriteFile(fn, data, 0644); err != nil {
		t.Fatal(err)
	}

	tr := &Tree{roots: map[string]*node{}, name: fn}
	tr.Load()

	if _, ok := tr.Find("h.com", "/u/550e8400-e29b-41d4-a716-446655440000"); ok {
		t.Error("v1 구체 UUID 노드가 그대로 남음 — 마이그레이션 안 됨")
	}
	got, ok := tr.Find("h.com", "/u/{uuid}")
	if !ok {
		t.Fatal("/u/{uuid} 로 병합되지 않음")
	}
	if got.Count != 5 {
		t.Errorf("count = %d, want 5 (3+2 합산)", got.Count)
	}
	if len(got.Methods) != 2 {
		t.Errorf("methods = %v, want [GET POST] 합집합", got.Methods)
	}
	if len(got.Params) != 1 || !got.Params[0].Required {
		t.Errorf("seen 합산 실패 — tab 이 required 여야 함(5/5): %+v", got.Params)
	}
	if got.Path != "/u/{uuid}" {
		t.Errorf("path = %q, want /u/{uuid} (repath 누락)", got.Path)
	}
	// 재요청용 구체 경로는 더 최근에 본 쪽이 남아야 한다.
	found := false
	for _, g := range tr.Targets() {
		if g.Path == "/u/6ba7b810-9dad-11d1-80b4-00c04fd430c8" {
			found = true
		}
	}
	if !found {
		t.Error("lastPath 가 최근(2026-08-18) 쪽으로 보존되지 않음")
	}
}

// childCount — host 트리에서 path 노드의 자식 수 (테스트 헬퍼).
func childCount(t *Tree, host, path string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur, ok := t.roots[host]
	if !ok {
		return -1
	}
	for _, s := range splitSegs(path) {
		if cur = cur.children[s]; cur == nil {
			return -1
		}
	}
	return len(cur.children)
}
