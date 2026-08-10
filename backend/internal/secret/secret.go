// Package secret — 서버 측 대칭 암호화 (§5.1 FR-1.4). 프로젝트 인증정보를 저장 전 암호화한다.
// AES-256-GCM(인증암호) + 파일 마스터 키(없으면 생성). PoC 수준: 실제론 KMS/HSM 권장.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"sync"
)

var (
	mu   sync.RWMutex
	aead cipher.AEAD
)

// Init — 마스터 키 로드(없으면 32바이트 생성). 이후 Encrypt/Decrypt 사용 가능.
func Init(keyPath string) error {
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	mu.Lock()
	aead = g
	mu.Unlock()
	return nil
}

// Ready — 키가 초기화됐는가.
func Ready() bool {
	mu.RLock()
	defer mu.RUnlock()
	return aead != nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != 32 {
			return nil, errors.New("secret: 키 길이 오류(32 필요)")
		}
		return data, nil
	}
	key := make([]byte, 32) // AES-256
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt — 평문 → base64(nonce||ciphertext).
func Encrypt(plaintext []byte) (string, error) {
	mu.RLock()
	g := aead
	mu.RUnlock()
	if g == nil {
		return "", errors.New("secret: 미초기화")
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := g.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt — base64(nonce||ciphertext) → 평문. 변조 시 오류(GCM 인증).
func Decrypt(b64 string) ([]byte, error) {
	mu.RLock()
	g := aead
	mu.RUnlock()
	if g == nil {
		return nil, errors.New("secret: 미초기화")
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	ns := g.NonceSize()
	if len(data) < ns {
		return nil, errors.New("secret: ciphertext 너무 짧음")
	}
	return g.Open(nil, data[:ns], data[ns:], nil)
}
