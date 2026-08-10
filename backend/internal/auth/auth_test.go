package auth

import (
	"net/http"
	"testing"
)

func TestInject(t *testing.T) {
	Set(Config{
		Cookies: map[string]string{"session": "s-val"},
		Headers: map[string]string{"Authorization": "Bearer t-val"},
	})
	req, _ := http.NewRequest("GET", "http://x/", nil)
	Inject(req)

	if got := req.Header.Get("Authorization"); got != "Bearer t-val" {
		t.Errorf("Authorization not injected: %q", got)
	}
	c, err := req.Cookie("session")
	if err != nil || c.Value != "s-val" {
		t.Errorf("session cookie not injected: %v %v", c, err)
	}
}

func TestSnapshotMasksValues(t *testing.T) {
	Set(Config{
		Cookies: map[string]string{"session": "SECRET"},
		Headers: map[string]string{"Authorization": "SECRET"},
	})
	snap := Snapshot()
	if len(snap["cookies"]) != 1 || snap["cookies"][0] != "session" {
		t.Errorf("cookies snapshot should be key-only: %v", snap["cookies"])
	}
	// 값이 새지 않아야 함
	for group, keys := range snap {
		for _, k := range keys {
			if k == "SECRET" {
				t.Errorf("secret value leaked in %s snapshot", group)
			}
		}
	}
}

func TestEnabled(t *testing.T) {
	Set(Config{})
	if Enabled() {
		t.Error("empty config → Enabled() false")
	}
	Set(Config{Cookies: map[string]string{"a": "b"}})
	if !Enabled() {
		t.Error("with cookie → Enabled() true")
	}
}

// 테넌트 격리(§5.1 Phase 2): 두 Injector 인스턴스는 서로의 인증상태를 침범하지 않는다.
func TestInjectorIsolation(t *testing.T) {
	a := New()
	b := New()
	a.Set(Config{Cookies: map[string]string{"session": "A"}})
	a.SetIdentities([]Identity{{Name: "admin", Privileged: true, Cookies: map[string]string{"session": "A"}}})
	b.Set(Config{Cookies: map[string]string{"session": "B"}})

	// a 의 요청엔 A 세션.
	ra, _ := http.NewRequest("GET", "http://x/", nil)
	a.Inject(ra)
	if c, _ := ra.Cookie("session"); c == nil || c.Value != "A" {
		t.Errorf("injector a should inject session=A, got %v", c)
	}
	// b 의 요청엔 B 세션 (a 의 SetIdentities/Set 이 b 에 영향 없음).
	rb, _ := http.NewRequest("GET", "http://x/", nil)
	b.Inject(rb)
	if c, _ := rb.Cookie("session"); c == nil || c.Value != "B" {
		t.Errorf("injector b should inject session=B, got %v", c)
	}
	// 신원 격리: a 는 admin(고권한) 보유, b 는 anon 만.
	if names := a.IdentityNames(); len(names) != 2 || names[1] != "admin" {
		t.Errorf("a identities = %v, want [anon admin]", names)
	}
	if names := b.IdentityNames(); len(names) != 1 {
		t.Errorf("b identities = %v, want [anon] only", names)
	}
	// b 의 admin 신원은 privileged 여야 함(위 a 것과 다른 인스턴스 확인).
	for _, id := range a.Identities() {
		if id.Name == "admin" && !id.Privileged {
			t.Error("a.admin should be privileged")
		}
	}
}
