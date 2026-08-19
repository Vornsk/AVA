package endpoints

import (
	"os"
	"testing"
)

// TestRecordSpecTagging — 명세 인제스트로 기록한 엔드포인트가 source=spec 으로 태깅된다 (이슈 #25).
func TestRecordSpecTagging(t *testing.T) {
	tr := NewTree()
	tr.RecordSpec("http", "h.com", "GET", "/users/v1", nil, false, "")
	tr.Record("http", "h.com", "GET", "/crawled", nil, false, "")

	spec, ok := tr.Find("h.com", "/users/v1")
	if !ok {
		t.Fatal("/users/v1 없음")
	}
	if spec.Source != srcSpec {
		t.Errorf("source = %q, want %q", spec.Source, srcSpec)
	}
	crawled, _ := tr.Find("h.com", "/crawled")
	if crawled.Source != "" {
		t.Errorf("크롤 기록에 출처가 붙음: %q", crawled.Source)
	}

	// Target(스캔 계층)에도 노출된다 — #5 라이브니스 면제가 스캔 시점에 출처를 본다.
	var got string
	for _, g := range tr.Targets() {
		if g.Path == "/users/v1" {
			got = g.Source
		}
	}
	if got != srcSpec {
		t.Errorf("Target.Source = %q, want %q", got, srcSpec)
	}
}

// TestSpecVarAbsorbsCrawledValue — ★ 이슈 #25 완료기준.
// 명세가 /users/v1/{username} 을 등록한 뒤 크롤이 /users/v1/alice 를 기록하면 노드가 1개여야 한다.
func TestSpecVarAbsorbsCrawledValue(t *testing.T) {
	tr := NewTree()
	tr.RecordSpec("http", "h.com", "GET", "/users/v1/{username}", nil, false, "")
	tr.Record("http", "h.com", "GET", "/users/v1/alice", nil, false, "")
	tr.Record("http", "h.com", "GET", "/users/v1/bob", nil, false, "")

	if n := childCount(tr, "h.com", "/users/v1"); n != 1 {
		t.Fatalf("/users/v1 자식 %d개 (want 1) — 명세 경로와 크롤 경로가 갈라졌다", n)
	}
	got, ok := tr.Find("h.com", "/users/v1/{username}")
	if !ok {
		t.Fatal("{username} 노드 없음")
	}
	// 명세 등록 자체가 1회로 계상된다(크롤러가 폼을 방문 없이 기록하는 것과 같은 취급) → 1+alice+bob.
	if got.Count != 3 {
		t.Errorf("흡수 count = %d, want 3 (명세 1 + alice + bob)", got.Count)
	}
	if got.Source != srcSpec {
		t.Errorf("흡수 뒤 source = %q, want spec (라이브니스 면제 대상)", got.Source)
	}
	// 구체 경로로도 조회된다 (Find 가 같은 규칙으로 하강).
	if _, ok := tr.Find("h.com", "/users/v1/alice"); !ok {
		t.Error("구체 경로 /users/v1/alice 조회 실패")
	}
}

// TestSpecLiteralSiblingsSurvive — ★ #24 실패의 재발 방지.
// 명세가 변수와 리터럴을 함께 선언하면 리터럴 형제는 흡수되면 안 된다.
// VAmPI /users/v1 밑에는 {username} 과 _debug·register·login 이 공존한다.
func TestSpecLiteralSiblingsSurvive(t *testing.T) {
	tr := NewTree()
	for _, p := range []string{"/users/v1/_debug", "/users/v1/register", "/users/v1/login", "/users/v1/{username}"} {
		tr.RecordSpec("http", "h.com", "GET", p, nil, false, "")
	}
	// 크롤이 같은 경로들을 다시 만난다.
	for _, p := range []string{"/users/v1/_debug", "/users/v1/register", "/users/v1/login", "/users/v1/carol"} {
		tr.Record("http", "h.com", "GET", p, nil, false, "")
	}
	for _, want := range []string{"/users/v1/_debug", "/users/v1/register", "/users/v1/login", "/users/v1/{username}"} {
		if _, ok := tr.Find("h.com", want); !ok {
			t.Errorf("%s 가 사라짐 — 명세 리터럴이 변수 자리로 삼켜졌다", want)
		}
	}
	if n := childCount(tr, "h.com", "/users/v1"); n != 4 {
		t.Errorf("/users/v1 자식 %d개 (want 4)", n)
	}
	// carol 만 {username} 으로 흡수됐다.
	u, _ := tr.Find("h.com", "/users/v1/{username}")
	if u.Count != 2 {
		t.Errorf("{username} count = %d, want 2 (명세 1 + carol)", u.Count)
	}
}

// TestSpecDeclareFoldsPriorCrawl — 크롤이 먼저 구체값을 만들어 둔 뒤 명세가 들어와도 합쳐진다.
// (정상 흐름은 인제스트 선행이지만, 순서가 뒤집혀도 트리가 갈라지지 않아야 한다.)
func TestSpecDeclareFoldsPriorCrawl(t *testing.T) {
	tr := NewTree()
	tr.Record("http", "h.com", "GET", "/users/v1/alice", nil, false, "")
	tr.Record("http", "h.com", "GET", "/users/v1/bob", nil, false, "")
	if n := childCount(tr, "h.com", "/users/v1"); n != 2 {
		t.Fatalf("사전 조건 실패: 자식 %d개", n)
	}
	tr.RecordSpec("http", "h.com", "GET", "/users/v1/{username}", nil, false, "")

	if n := childCount(tr, "h.com", "/users/v1"); n != 1 {
		t.Fatalf("명세 선언 뒤에도 자식 %d개 (want 1)", n)
	}
	got, _ := tr.Find("h.com", "/users/v1/{username}")
	if got.Count != 3 {
		t.Errorf("병합 count = %d, want 3 (alice+bob 합산 + 명세 1)", got.Count)
	}
	if got.Path != "/users/v1/{username}" {
		t.Errorf("path = %q (repath 누락)", got.Path)
	}
}

// TestSpecVarIgnoresValueShape — 명세 선언 자리는 값 모양을 따지지 않는다.
// 휴리스틱(#24)은 looksLikeValue 만 흡수하지만, 명세는 확정 정보이므로 "alice" 도 흡수한다.
func TestSpecVarIgnoresValueShape(t *testing.T) {
	if looksLikeValue("alice") {
		t.Fatal("사전 조건: alice 는 값 모양이 아니어야 한다")
	}
	tr := NewTree()
	tr.RecordSpec("http", "h.com", "GET", "/u/{name}", nil, false, "")
	tr.Record("http", "h.com", "GET", "/u/alice", nil, false, "")
	if n := childCount(tr, "h.com", "/u"); n != 1 {
		t.Errorf("자식 %d개 — 명세 자리가 값 모양을 따졌다", n)
	}
}

// TestSpecSourcePersistence — source·변수 자리가 저장/복원을 왕복한다.
func TestSpecSourcePersistence(t *testing.T) {
	const fn = "test_spec_ep.json"
	defer os.Remove(fn)

	tr := &Tree{roots: map[string]*node{}, name: fn}
	tr.RecordSpec("http", "h.com", "GET", "/users/v1/{username}", []Param{{Name: "q", In: "query"}}, false, "")
	tr.Record("http", "h.com", "GET", "/users/v1/alice", nil, false, "")

	tr2 := &Tree{roots: map[string]*node{}, name: fn}
	tr2.Load()

	got, ok := tr2.Find("h.com", "/users/v1/{username}")
	if !ok {
		t.Fatal("복원 실패")
	}
	if got.Source != srcSpec {
		t.Errorf("복원 source = %q, want spec", got.Source)
	}
	// 복원 뒤에도 변수 자리가 살아 있어 새 값을 흡수한다.
	tr2.Record("http", "h.com", "GET", "/users/v1/dave", nil, false, "")
	if n := childCount(tr2, "h.com", "/users/v1"); n != 1 {
		t.Errorf("복원 뒤 자식 %d개 — varChild 가 왕복하지 않았다", n)
	}
}

// TestLabelsPersist — 의미 라벨(이슈 #41)이 저장/복원을 왕복한다(E5/E6 가 재시작 후에도 읽는다).
func TestLabelsPersist(t *testing.T) {
	const fn = "test_labels_ep.json"
	defer os.Remove(fn)

	tr := &Tree{roots: map[string]*node{}, name: fn}
	tr.Record("http", "h.com", "GET", "/admin", nil, false, "")
	if !tr.SetLabels("h.com", "/admin", []string{"admin", "pii"}) {
		t.Fatal("SetLabels 실패")
	}
	if tr.SetLabels("h.com", "/nope", []string{"x"}) {
		t.Error("없는 노드에 SetLabels 가 true 를 반환")
	}

	tr2 := &Tree{roots: map[string]*node{}, name: fn}
	tr2.Load()
	var got []string
	for _, tg := range tr2.Targets() {
		if tg.Path == "/admin" {
			got = tg.Labels
		}
	}
	if len(got) != 2 || got[0] != "admin" || got[1] != "pii" {
		t.Errorf("복원 라벨=%v (want [admin pii])", got)
	}
}

// TestSpecNotAbsorbedByHeuristic — 휴리스틱(#24)이 만든 {slug} 자리가 명세 기록을 삼키면 안 된다.
func TestSpecNotAbsorbedByHeuristic(t *testing.T) {
	tr := NewTree()
	for i := 0; i < slugMinSiblings; i++ {
		tr.Record("https", "h.com", "GET", slugPath(i), nil, false, "")
	}
	if _, ok := tr.Find("h.com", "/blog/{slug}"); !ok {
		t.Fatal("사전 조건: {slug} 로 접혀 있어야 한다")
	}
	tr.RecordSpec("https", "h.com", "GET", "/blog/archive-2026-index", nil, false, "")
	if _, ok := tr.Find("h.com", "/blog/archive-2026-index"); !ok {
		t.Error("명세 기록이 {slug} 로 삼켜졌다 — 명세는 트리 구조의 기준이다")
	}
}
