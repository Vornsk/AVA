// Package session — 로그인 세션 (§5.1 FR-1.4). 서버 측 토큰→사용자 매핑 + 만료.
// 토큰은 crypto/rand 로 생성하고 쿠키(httpOnly)로만 전달한다. 단일 인스턴스 인메모리 저장.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// CookieName — 세션 쿠키 이름.
const CookieName = "cg_sid"

// TTL — 세션 수명.
const TTL = 8 * time.Hour

type entry struct {
	userID string
	expiry time.Time
}

var (
	mu    sync.Mutex
	store = map[string]entry{}
)

// New — 사용자에 대한 새 세션 토큰 발급.
func New(userID string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	mu.Lock()
	store[tok] = entry{userID: userID, expiry: time.Now().Add(TTL)}
	mu.Unlock()
	return tok
}

// UserID — 토큰이 유효하면 사용자 id 반환. 만료 시 제거.
func UserID(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	mu.Lock()
	defer mu.Unlock()
	e, ok := store[tok]
	if !ok {
		return "", false
	}
	if time.Now().After(e.expiry) {
		delete(store, tok)
		return "", false
	}
	return e.userID, true
}

// Delete — 세션 무효화(로그아웃).
func Delete(tok string) {
	mu.Lock()
	delete(store, tok)
	mu.Unlock()
}
