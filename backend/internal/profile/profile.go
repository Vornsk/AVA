// Package profile — 대상 프로파일 (FR-3.9): 자주 쓰는 대상+탐지기 선택을 이름으로 저장·재사용.
package profile

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
)

// Profile — 저장된 스캔 선택(대상 필터 + 탐지기 + 자동 여부).
type Profile struct {
	Name         string   `json:"name"`
	Hosts        []string `json:"hosts,omitempty"`
	PathContains string   `json:"path_contains,omitempty"`
	Detectors    []string `json:"detectors,omitempty"`
	Auto         bool     `json:"auto,omitempty"` // 공격면 넓은 대상 자동선정
}

var (
	mu    sync.Mutex
	store = map[string]Profile{}
)

// Save — 프로파일 저장(이름 키). profiles.json 갱신.
func Save(p Profile) {
	mu.Lock()
	store[p.Name] = p
	snap := snapshotLocked()
	mu.Unlock()
	data, _ := json.MarshalIndent(snap, "", "  ")
	_ = os.WriteFile("profiles.json", data, 0644)
}

// Get — 이름으로 프로파일 조회.
func Get(name string) (Profile, bool) {
	mu.Lock()
	defer mu.Unlock()
	p, ok := store[name]
	return p, ok
}

// List — 전체 프로파일(이름순).
func List() []Profile {
	mu.Lock()
	defer mu.Unlock()
	return snapshotLocked()
}

func snapshotLocked() []Profile {
	names := make([]string, 0, len(store))
	for n := range store {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Profile, 0, len(names))
	for _, n := range names {
		out = append(out, store[n])
	}
	return out
}
