package profile

import "testing"

func TestSaveGetList(t *testing.T) {
	Save(Profile{Name: "web", Hosts: []string{"a.com"}, Auto: true, Detectors: []string{"sec-headers"}})
	Save(Profile{Name: "api", PathContains: "/api"})

	if p, ok := Get("web"); !ok || !p.Auto || len(p.Hosts) != 1 || p.Hosts[0] != "a.com" {
		t.Errorf("Get(web) = %+v, ok=%v", p, ok)
	}
	if _, ok := Get("nonexistent"); ok {
		t.Error("Get(nonexistent) should be false")
	}

	l := List()
	if len(l) != 2 {
		t.Fatalf("List len = %d, want 2", len(l))
	}
	if l[0].Name != "api" || l[1].Name != "web" { // 이름순 정렬
		t.Errorf("List not sorted: %v", []string{l[0].Name, l[1].Name})
	}
}
