// Package user — 역할·권한(RBAC) (§5.1 FR-1.4). 리더/수행원 역할과 액션별 권한을 정의하고,
// 현재 사용자(누가 조작 중인지)를 관리한다. 실제 로그인/세션·비밀번호는 후속(Phase 3b);
// 여기서는 인가 모델과 감사(누가 무엇을)를 위한 신원만 다룬다.
package user

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// Role — 사용자 역할 (§5.1). 리더는 프로젝트/사용자 관리·승인, 수행원은 진단 수행.
type Role string

const (
	RoleLeader  Role = "leader"  // 리더 (서버 호스팅·프로젝트/사용자 관리·승인)
	RoleAnalyst Role = "analyst" // 수행원 (진단 수행)
)

// User — 진단자 (§3 확장). PasswordHash 는 API JSON 에 절대 노출하지 않는다(json:"-").
type User struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Role         Role   `json:"role"`
	PasswordHash string `json:"-"` // bcrypt. 저장은 별도 표현으로만.
}

// perms — 액션별 허용 역할. 리더 전용은 관리·승인 계열.
var perms = map[string][]Role{
	"project:create":      {RoleLeader},
	"project:delete":      {RoleLeader},
	"project:credentials": {RoleLeader}, // 인증정보 설정(암호화) — 리더 전용 (FR-1.4)
	"project:members":     {RoleLeader}, // 프로젝트 멤버 관리 — 리더 전용 (FR-1.4 ACL)
	"project:activate":    {RoleLeader, RoleAnalyst},
	"scan:run":            {RoleLeader, RoleAnalyst},
	"rule:promote":        {RoleLeader},
	"finding:confirm":     {RoleLeader, RoleAnalyst},
	"finding:clear":       {RoleLeader}, // 도출 항목 전체 초기화 — 파괴적, 리더 전용
	"endpoint:clear":      {RoleLeader}, // 공격면(엔드포인트) 전체 초기화/개별 삭제 — 파괴적, 리더 전용
	"user:manage":         {RoleLeader},
	"proxy:control":       {RoleLeader}, // 공용 프록시 캡처 on/off — 리더 전용 (이슈 #5)
	"llm:policy":          {RoleLeader}, // 판단 프롬프트 정책 변경 — 리더 전용 (이슈 #53)
}

// Can — 역할이 액션을 수행할 수 있는가.
func Can(r Role, action string) bool {
	for _, allowed := range perms[action] {
		if allowed == r {
			return true
		}
	}
	return false
}

// Actions — 특정 역할이 가진 권한 목록 (UI 노출용).
func Actions(r Role) []string {
	var out []string
	for a, roles := range perms {
		for _, x := range roles {
			if x == r {
				out = append(out, a)
				break
			}
		}
	}
	return out
}

const file = "users.json"

var (
	mu        sync.Mutex
	store     []User
	currentID string
	seq       int
)

// storedUser — 파일 저장용(해시 포함). API 응답엔 절대 쓰지 않는다.
type storedUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role Role   `json:"role"`
	Hash string `json:"hash"`
}

type persisted struct {
	Users   []storedUser `json:"users"`
	Current string       `json:"current"`
}

// Load — 파일에서 사용자 복원(해시 포함).
func Load() {
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}
	var p persisted
	if json.Unmarshal(data, &p) != nil {
		return
	}
	mu.Lock()
	store = nil
	for _, su := range p.Users {
		store = append(store, User{ID: su.ID, Name: su.Name, Role: su.Role, PasswordHash: su.Hash})
		if n, _ := strconv.Atoi(strings.TrimPrefix(su.ID, "u-")); n > seq {
			seq = n
		}
	}
	currentID = p.Current
	mu.Unlock()
}

func persist() { // 호출부가 mu 를 잡고 있어야 함
	out := make([]storedUser, 0, len(store))
	for _, u := range store {
		out = append(out, storedUser{ID: u.ID, Name: u.Name, Role: u.Role, Hash: u.PasswordHash})
	}
	data, _ := json.MarshalIndent(persisted{Users: out, Current: currentID}, "", "  ")
	_ = os.WriteFile(file, data, 0644)
}

// Seed — 사용자가 없으면 기본 리더+수행원 생성(부트스트랩). 데모 비밀번호(운영 시 변경 필수).
func Seed() {
	mu.Lock()
	empty := len(store) == 0
	mu.Unlock()
	if empty {
		Create("leader", RoleLeader, "leader123")    // 첫 사용자 = 현재 사용자
		Create("analyst", RoleAnalyst, "analyst123") // 데모용 계정
	}
}

// Create — 사용자 추가(비밀번호 bcrypt 해시). 첫 사용자는 자동 현재 사용자.
func Create(name string, role Role, password string) User {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	mu.Lock()
	seq++
	u := User{ID: fmt.Sprintf("u-%d", seq), Name: name, Role: role, PasswordHash: string(hash)}
	store = append(store, u)
	if currentID == "" {
		currentID = u.ID
	}
	persist()
	mu.Unlock()
	return u
}

// Delete — id로 사용자 삭제 (user:manage). 성공 시 true. 삭제된 사용자면 currentID도 해제.
func Delete(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	for i := range store {
		if store[i].ID == id {
			store = append(store[:i], store[i+1:]...)
			if currentID == id {
				currentID = ""
			}
			persist()
			return true
		}
	}
	return false
}

// SetPassword — id 사용자의 비밀번호를 bcrypt로 재설정 (user:manage). 성공 시 true.
func SetPassword(id, password string) bool {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	for i := range store {
		if store[i].ID == id {
			store[i].PasswordHash = string(hash)
			persist()
			return true
		}
	}
	return false
}

// Count — 특정 역할의 사용자 수 (마지막 리더 삭제 방지 등에 사용).
func Count(role Role) int {
	mu.Lock()
	defer mu.Unlock()
	n := 0
	for i := range store {
		if store[i].Role == role {
			n++
		}
	}
	return n
}

// Authenticate — 이름+비밀번호 검증. 성공 시 사용자 반환 (§5.1 FR-1.4). 타이밍 안전(bcrypt).
func Authenticate(name, password string) (User, bool) {
	mu.Lock()
	var found *User
	for i := range store {
		if store[i].Name == name {
			u := store[i]
			found = &u
			break
		}
	}
	mu.Unlock()
	if found == nil {
		return User{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(found.PasswordHash), []byte(password)) != nil {
		return User{}, false
	}
	return *found, true
}

// List — 전체 사용자.
func List() []User {
	mu.Lock()
	defer mu.Unlock()
	return append([]User(nil), store...)
}

// Get — id 조회.
func Get(id string) (User, bool) {
	mu.Lock()
	defer mu.Unlock()
	for _, u := range store {
		if u.ID == id {
			return u, true
		}
	}
	return User{}, false
}

// Current — 현재 사용자.
func Current() (User, bool) {
	mu.Lock()
	id := currentID
	mu.Unlock()
	return Get(id)
}

// SetCurrent — 현재 사용자 전환 (단일 인스턴스 데모용; 실제론 로그인 세션).
func SetCurrent(id string) bool {
	mu.Lock()
	defer mu.Unlock()
	for _, u := range store {
		if u.ID == id {
			currentID = id
			persist()
			return true
		}
	}
	return false
}

// Reset — 테스트용.
func Reset() {
	mu.Lock()
	store, currentID, seq = nil, "", 0
	mu.Unlock()
}
