package scope

import "testing"

func TestInScope(t *testing.T) {
	Configure([]string{"example.com", "httpbin.org"}, nil, nil)
	if !InScope("example.com") {
		t.Error("example.com should be in scope")
	}
	if !InScope("www.example.com") {
		t.Error("subdomain www.example.com should match")
	}
	if InScope("evil.com") {
		t.Error("evil.com should be out of scope")
	}
	if InScope("notexample.com") {
		t.Error("notexample.com must not match example.com (suffix-abuse)")
	}
}

func TestAllowedExclude(t *testing.T) {
	Configure([]string{"example.com"}, nil, []string{"/secret"})
	if ok, _ := Allowed("example.com", "/public"); !ok {
		t.Error("/public should be allowed")
	}
	if ok, reason := Allowed("example.com", "/secret/1"); ok {
		t.Errorf("/secret should be excluded (reason=%q)", reason)
	}
	if ok, _ := Allowed("evil.com", "/public"); ok {
		t.Error("out-of-scope host should be blocked")
	}
}

func TestAllowedAllowList(t *testing.T) {
	Configure([]string{"example.com"}, []string{"^/api/"}, nil)
	if ok, _ := Allowed("example.com", "/api/users"); !ok {
		t.Error("/api/ should be allowed")
	}
	if ok, _ := Allowed("example.com", "/web"); ok {
		t.Error("/web not in allow-list → should be blocked")
	}
}

func TestAddRemove(t *testing.T) {
	Configure([]string{"a.com"}, nil, nil)
	if !Add("b.com") {
		t.Error("Add(b.com) should return true")
	}
	if Add("b.com") {
		t.Error("duplicate Add should return false")
	}
	if !InScope("b.com") {
		t.Error("b.com should be in scope after Add")
	}
	if !Remove("b.com") {
		t.Error("Remove(b.com) should return true")
	}
	if InScope("b.com") {
		t.Error("b.com should be gone after Remove")
	}
}
