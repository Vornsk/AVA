package crawler

import (
	"net/url"
	"testing"
)

// 정상 중첩된 폼 — 필드가 그대로 잡혀야 한다(회귀 방지).
func TestExtractNestedForm(t *testing.T) {
	base, _ := url.Parse("http://t/")
	html := `<html><body><form action="/a" method="post">
		<input name="user"><input name="pw"><select name="role"></select></form></body></html>`
	_, forms := extract(html, base)
	if len(forms) != 1 || len(forms[0].fields) != 3 {
		t.Fatalf("nested form fields = %v", formFields(forms))
	}
}

// ★ 이슈 핵심 — <table> 직속 <form> 은 HTML5 foster-parenting 으로 필드가 폼 밖으로
// 밀린다. 문서 순서로 직전 폼에 이어 붙여 복원해야 한다. 옛 한국 쇼핑몰의 전형 구조다.
func TestExtractFosterParentedForm(t *testing.T) {
	base, _ := url.Parse("http://t/")
	// 실제 옛 쇼핑몰 구조: 검색·로그인 폼이 각각 테이블 레이아웃 안에 있다. 필드는 tr/td 안에
	// 있어 위치는 보존되지만, <form> 이 <table> 직속이라 자식으로 안 잡힌다(foster-parenting).
	// 문서 순서로 직전 폼에 이어 복원한다.
	html := `<html><body>
	<table><form action="/search" method="post">
		<tr><td><input type="hidden" name="mode"><input name="q"></td></tr>
	</form></table>
	<table><form action="/login" method="post">
		<tr><td><input type="hidden" name="csrf"><input name="id"></td></tr>
		<tr><td><input name="pw"></td></tr>
	</form></table>
	</body></html>`
	_, forms := extract(html, base)
	byAction := map[string][]string{}
	for _, f := range forms {
		byAction[f.action] = f.fields
	}
	search := byAction["http://t/search"]
	login := byAction["http://t/login"]
	if len(search) != 2 || search[0] != "mode" || search[1] != "q" {
		t.Errorf("search form fields = %v, want [mode q]", search)
	}
	if len(login) != 3 {
		t.Errorf("login form fields = %v, want [csrf id pw]", login)
	}
	// 로그인 필드가 검색 폼으로 새면 안 된다(직전 폼 경계 준수)
	for _, name := range search {
		if name == "id" || name == "pw" || name == "csrf" {
			t.Errorf("로그인 필드가 검색 폼으로 샜다: %v", search)
		}
	}
}

func formFields(fs []form) [][]string {
	out := make([][]string, len(fs))
	for i, f := range fs {
		out[i] = f.fields
	}
	return out
}
