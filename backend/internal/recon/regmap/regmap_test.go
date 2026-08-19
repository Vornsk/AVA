package regmap

import (
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
