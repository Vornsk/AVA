package regmap

import (
	"encoding/json"
	"strings"
	"testing"

	"proxypoc/internal/checklist"
	"proxypoc/internal/endpoints"
)

func findItem(rep Report, scheme checklist.Scheme, id string) (ItemCandidates, bool) {
	for _, s := range rep.Schemes {
		if s.Scheme != scheme {
			continue
		}
		for _, it := range s.Items {
			if it.CheckItem.ID == id {
				return it, true
			}
		}
	}
	return ItemCandidates{}, false
}

func tgt(host, path string, labels []string, authOnly bool) endpoints.Target {
	return endpoints.Target{Host: host, Path: path, Methods: []string{"GET"}, Labels: labels, AuthOnly: authOnly}
}

// TestBuild — ★ 이슈 #42: 라벨이 붙은 대상이 규제 점검항목 후보로 매핑된다.
func TestBuild(t *testing.T) {
	checklist.SetSelected(nil) // 전체 스킴
	targets := []endpoints.Target{
		tgt("h.com", "/checkout", []string{"payment"}, false),
		tgt("h.com", "/upload", []string{"upload"}, false),
		tgt("h.com", "/admin/users", []string{"admin", "pii"}, false),
		tgt("h.com", "/assets/x.css", []string{"static"}, false), // 매핑 없음
		tgt("h.com", "/about", nil, false),                       // 라벨 없음
	}
	rep := Build(targets)

	// Labeled = 적용 점검항목이 나온 엔드포인트(구조적 static·라벨없음 제외): checkout·upload·admin.
	if rep.Endpoints != 5 || rep.Labeled != 3 {
		t.Fatalf("endpoints=%d labeled=%d (want 5,3)", rep.Endpoints, rep.Labeled)
	}
	// payment → 전자금융 거래 보안 항목(1)에 /checkout 후보.
	if it, ok := findItem(rep, checklist.SchemeFinance, "1"); !ok {
		t.Error("전자금융 항목 1(payment) 미매핑")
	} else if it.Count != 1 || it.Endpoints[0] != "h.com/checkout" {
		t.Errorf("항목 1 후보=%v count=%d", it.Endpoints, it.Count)
	}
	// admin → 관리자 페이지 접근통제(56, 전자금융 / AE, KII).
	if _, ok := findItem(rep, checklist.SchemeFinance, "56"); !ok {
		t.Error("전자금융 항목 56(admin 접근통제) 미매핑")
	}
	// static 라벨은 규제 후보를 만들지 않는다.
	for _, s := range rep.Schemes {
		for _, it := range s.Items {
			for _, l := range it.Labels {
				if l == "static" || l == "api" || l == "other" {
					t.Errorf("구조적 라벨 %q 가 규제 매핑에 들어옴 (항목 %s)", l, it.CheckItem.ID)
				}
			}
		}
	}
}

// TestAccessControlCombo — ★ auth-only(E1) + admin(E4) 조합이 접근통제 항목에 강조 표시된다.
func TestAccessControlCombo(t *testing.T) {
	checklist.SetSelected(nil)
	// 같은 admin 라벨이라도 auth-only 여부로 접근통제 강조가 갈린다.
	hidden := tgt("h.com", "/admin/secret", []string{"admin"}, true) // 인증 뒤 관리 표면
	plain := tgt("h.com", "/admin/public", []string{"admin"}, false) // 그냥 관리 라벨
	rep := Build([]endpoints.Target{hidden, plain})

	if rep.AccessCtl != 1 {
		t.Errorf("접근통제 후보(E1+E4)=%d (want 1)", rep.AccessCtl)
	}
	// 접근통제 vuln 을 참조하는 항목은 AccessControl=true 여야 한다(hidden 이 걸리므로).
	it, ok := findItem(rep, checklist.SchemeFinance, "56")
	if !ok {
		t.Fatal("항목 56 없음")
	}
	if !it.AccessControl {
		t.Error("auth-only+admin 인데 접근통제 강조(AccessControl)가 꺼져 있다")
	}
	if it.Count != 2 { // 두 관리 엔드포인트 모두 후보
		t.Errorf("항목 56 후보 수=%d (want 2)", it.Count)
	}
}

// TestSelectedSchemeOnly — 선택된 스킴만 집계한다.
func TestSelectedSchemeOnly(t *testing.T) {
	checklist.SetSelected([]checklist.Scheme{checklist.SchemeFinance})
	defer checklist.SetSelected(nil)
	rep := Build([]endpoints.Target{tgt("h.com", "/admin", []string{"admin"}, false)})
	for _, s := range rep.Schemes {
		if s.Scheme != checklist.SchemeFinance {
			t.Errorf("미선택 스킴 %q 가 집계됨", s.Scheme)
		}
	}
}

// TestGaps — ★ 이슈 #43: 라벨로 도달 가능하나 발견 0건인 점검항목이 "공백"으로 나온다.
func TestGaps(t *testing.T) {
	checklist.SetSelected([]checklist.Scheme{checklist.SchemeFinance})
	defer checklist.SetSelected(nil)
	// payment 하나만 발견 — 나머지 라벨(admin·pii·upload·auth·search)의 항목은 전부 공백이어야 한다.
	rep := Build([]endpoints.Target{tgt("h.com", "/checkout", []string{"payment"}, false)})

	var fin SchemeReport
	for _, s := range rep.Schemes {
		if s.Scheme == checklist.SchemeFinance {
			fin = s
		}
	}
	if fin.Applicable == 0 || len(fin.Gaps) == 0 {
		t.Fatalf("커버=%d 공백=%d — 둘 다 나와야 한다", fin.Applicable, len(fin.Gaps))
	}
	if fin.Mappable != fin.Applicable+len(fin.Gaps) {
		t.Errorf("모수 불일치: mappable=%d applicable=%d gaps=%d", fin.Mappable, fin.Applicable, len(fin.Gaps))
	}
	// 공백은 발견 0건이고, 커버된 항목과 겹치지 않는다.
	covered := map[string]bool{}
	for _, it := range fin.Items {
		covered[it.CheckItem.ID] = true
	}
	for _, g := range fin.Gaps {
		if g.Count != 0 || len(g.Endpoints) != 0 {
			t.Errorf("공백 항목 %s 에 후보가 있다 (count=%d)", g.CheckItem.ID, g.Count)
		}
		if covered[g.CheckItem.ID] {
			t.Errorf("항목 %s 가 커버·공백 양쪽에 있다", g.CheckItem.ID)
		}
		if len(g.Labels) == 0 {
			t.Errorf("공백 항목 %s 에 유발 라벨이 비었다 — 무슨 라벨을 찾으면 메워지는지 알 수 없다", g.CheckItem.ID)
		}
	}
	// 항목 1(거래 보안, payment)은 커버 쪽에만.
	if _, ok := findItem(rep, checklist.SchemeFinance, "1"); !ok {
		t.Error("payment 로 커버된 항목 1 이 Items 에 없다")
	}
}

// TestGapsMappableUniverse — 모수는 "라벨로 도달 가능한 항목"이다. 전체 항목표가 아니다.
func TestGapsMappableUniverse(t *testing.T) {
	checklist.SetSelected([]checklist.Scheme{checklist.SchemeFinance})
	defer checklist.SetSelected(nil)
	rep := Build([]endpoints.Target{tgt("h.com", "/checkout", []string{"payment"}, false)})

	// 라벨 매핑으로 실제 도달 가능한 항목 집합.
	want := map[string]bool{}
	for _, l := range checklist.SemanticLabels() {
		for _, ci := range checklist.CheckItemsForLabel(l) {
			if ci.Scheme == checklist.SchemeFinance {
				want[ci.ID] = true
			}
		}
	}
	got := 0
	for _, s := range rep.Schemes {
		if s.Scheme != checklist.SchemeFinance {
			continue
		}
		got = s.Mappable
		for _, it := range append(append([]ItemCandidates{}, s.Items...), s.Gaps...) {
			if !want[it.CheckItem.ID] {
				t.Errorf("라벨로 도달 불가한 항목 %s 가 모수에 들어옴", it.CheckItem.ID)
			}
		}
	}
	if got != len(want) {
		t.Errorf("모수=%d (want %d) — 전체 항목표를 세면 안 된다", got, len(want))
	}
	if len(want) >= len(checklist.CheckItemsByScheme(checklist.SchemeFinance)) {
		t.Errorf("전자금융 전체(%d) 대비 라벨 도달 가능(%d) — 모수가 좁아야 공백이 신호가 된다",
			len(checklist.CheckItemsByScheme(checklist.SchemeFinance)), len(want))
	}
}

// TestItemsNeverNilWhenSchemeHasOnlyGaps — 실서비스 회귀 재현: 엔드포인트가 없어서(또는
// 라벨이 하나도 안 붙어서) 어떤 스킴의 실제 후보(Items)가 0건이고 공백(Gaps)만 있으면,
// byScheme 맵 조회가 nil 슬라이스를 돌려주고 그게 그대로 SchemeReport.Items 에 들어간다.
// Items 필드엔 omitempty 가 없어 nil 이면 JSON이 "items:null"이 되고, 프론트 s.items.map()이
// "Cannot read properties of null" 로 죽는다(실제로 겪음 — 공격면이 거의 비었을 때 발생).
func TestItemsNeverNilWhenSchemeHasOnlyGaps(t *testing.T) {
	checklist.SetSelected([]checklist.Scheme{checklist.SchemeFinance})
	defer checklist.SetSelected(nil)

	rep := Build(nil) // 엔드포인트 0개 → 모든 매핑 가능 항목이 공백, 실제 후보(Items)는 0건

	var fin SchemeReport
	found := false
	for _, s := range rep.Schemes {
		if s.Scheme == checklist.SchemeFinance {
			fin, found = s, true
		}
	}
	if !found {
		t.Fatal("공백만 있어도 스킴 자체는 리포트에 나와야 한다")
	}
	if fin.Applicable != 0 || len(fin.Gaps) == 0 {
		t.Fatalf("Applicable=%d Gaps=%d — 후보 0·공백 있음 케이스가 아님(테스트 전제 확인 필요)", fin.Applicable, len(fin.Gaps))
	}
	if fin.Items == nil {
		t.Fatal("Items 가 nil — JSON 직렬화 시 null 이 돼 프론트 .map() 이 깨진다")
	}
	b, err := json.Marshal(fin)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(b); !strings.Contains(got, `"items":[]`) {
		t.Errorf("직렬화 결과에 \"items\":[] 가 없음(null 이 됐을 가능성): %s", got)
	}
}
