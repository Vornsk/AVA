package project

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"proxypoc/internal/secret"
)

func TestCredentialsEncryptedAtRest(t *testing.T) {
	Reset()
	defer func() { Reset(); _ = os.Remove(file) }()
	if err := secret.Init(filepath.Join(t.TempDir(), "k.key")); err != nil {
		t.Fatalf("secret.Init: %v", err)
	}

	p := Create(Project{Name: "acme", Scope: []string{"acme.test"}})
	creds := Credentials{
		Cookies: map[string]string{"SESSION": "s3cr3t-token"},
		Headers: map[string]string{"Authorization": "Bearer abc"},
		Identities: map[string]IdentityCreds{
			"admin": {Cookies: map[string]string{"SESSION": "admin-tok"}},
		},
	}
	if err := SetCredentials(p.ID, creds); err != nil {
		t.Fatalf("SetCredentials: %v", err)
	}

	// 저장 파일에 평문 자격증명이 없어야 한다.
	raw, _ := os.ReadFile(file)
	for _, secretVal := range []string{"s3cr3t-token", "Bearer abc", "admin-tok"} {
		if strings.Contains(string(raw), secretVal) {
			t.Errorf("projects.json 에 평문 노출: %q", secretVal)
		}
	}

	// 복호화하면 원본과 동일.
	got, ok := GetCredentials(p.ID)
	if !ok || got.Cookies["SESSION"] != "s3cr3t-token" || got.Identities["admin"].Cookies["SESSION"] != "admin-tok" {
		t.Errorf("복호화 불일치: %+v ok=%v", got, ok)
	}

	// 마스킹 요약은 이름만 노출.
	s := CredentialSummary(p.ID)
	if !s.HasCreds || len(s.Cookies) != 1 || s.Cookies[0] != "SESSION" {
		t.Errorf("요약 오류: %+v", s)
	}
}
