package checklist

import "testing"

func hasCI(items []CheckItem, id string) bool {
	for _, c := range items {
		if c.ID == id {
			return true
		}
	}
	return false
}

// TestCheckItemsForLabel — ★ 이슈 #42: 대표 라벨이 올바른 점검항목에 연결된다(라벨→vuln→checkitem).
func TestCheckItemsForLabel(t *testing.T) {
	cases := []struct {
		label string
		want  []string // 반드시 포함해야 할 checkitem id(스킴 혼합)
	}{
		{"payment", []string{"1", "63"}},            // 전자금융 거래 보안(vuln.txn-security)
		{"upload", []string{"FU", "20"}},            // 악성 파일 업로드
		{"admin", []string{"IN", "AE", "21", "56"}}, // 접근통제·관리자 페이지
		{"pii", []string{"IL", "38"}},               // 정보 누출 / 중요정보 평문노출
		{"search", []string{"SI", "19"}},            // SQL 인젝션
		{"auth", []string{"IA", "37", "22"}},        // 불충분한 인증 / 인증정보 관리
	}
	for _, c := range cases {
		got := CheckItemsForLabel(c.label)
		if len(got) == 0 {
			t.Errorf("label %q → 점검항목 0건", c.label)
		}
		for _, id := range c.want {
			if !hasCI(got, id) {
				t.Errorf("label %q → %q 미포함 (got %d건)", c.label, id, len(got))
			}
		}
	}
	// 구조적 라벨은 규제 매핑이 없다.
	for _, l := range []string{"api", "static", "other", ""} {
		if got := CheckItemsForLabel(l); len(got) != 0 {
			t.Errorf("구조적 라벨 %q 에 매핑이 붙음: %d건", l, len(got))
		}
	}
}

// TestLabelMapValidates — 라벨→vuln 이 모두 존재하는 vuln 을 가리킨다(항목표 무결성).
func TestLabelMapValidates(t *testing.T) {
	issues := Validate(map[string]bool{}) // detector 미존재는 무시(라벨 이슈만 본다)
	for _, iss := range issues {
		if len(iss) >= 5 && iss[:5] == "label" {
			t.Errorf("라벨 매핑 무결성 위반: %s", iss)
		}
	}
	// 모든 라벨이 최소 하나의 vuln 을 가진다.
	for _, l := range []string{"auth", "payment", "upload", "admin", "pii", "search"} {
		if len(VulnsForLabel(l)) == 0 {
			t.Errorf("label %q 에 vuln 매핑 없음", l)
		}
	}
}
