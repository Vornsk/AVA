package secret

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptRoundTrip(t *testing.T) {
	key := filepath.Join(t.TempDir(), "k.key")
	if err := Init(key); err != nil {
		t.Fatalf("Init: %v", err)
	}
	pt := []byte(`{"cookie":"SESSION=abc","rrn":"900101-1234567"}`)
	ct, err := Encrypt(pt)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// 암호문에 평문 조각이 없어야 한다.
	if containsSub(ct, "SESSION") || containsSub(ct, "900101") {
		t.Error("암호문에 평문 노출")
	}
	got, err := Decrypt(ct)
	if err != nil || string(got) != string(pt) {
		t.Fatalf("Decrypt=%q err=%v", got, err)
	}
	// 변조 감지 (GCM 인증).
	bad := ct[:len(ct)-2] + "AA"
	if _, err := Decrypt(bad); err == nil {
		t.Error("변조된 ciphertext 가 통과됨")
	}
}

func TestKeyPersistsAndReloads(t *testing.T) {
	key := filepath.Join(t.TempDir(), "k.key")
	Init(key)
	ct, _ := Encrypt([]byte("hello"))
	// 같은 키 파일로 재초기화 → 복호화 가능해야.
	Init(key)
	if got, err := Decrypt(ct); err != nil || string(got) != "hello" {
		t.Errorf("재로드 후 복호화 실패: %q %v", got, err)
	}
	if fi, err := os.Stat(key); err != nil || fi.Size() != 32 {
		t.Errorf("키 파일 32바이트여야, %v", err)
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
