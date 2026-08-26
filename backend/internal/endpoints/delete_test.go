package endpoints

import (
	"os"
	"testing"
)

// TestDeleteNode — 노드 1개를 지우면 그 서브트리만 사라지고 형제는 남아야 한다.
func TestDeleteNode(t *testing.T) {
	tr := NewTree()
	tr.Record("http", "h.com", "GET", "/api/users/alice", nil, false, "")
	tr.Record("http", "h.com", "GET", "/api/orders/alice", nil, false, "")

	if !tr.Delete("h.com", "/api/users") {
		t.Fatal("Delete 실패")
	}
	if _, ok := tr.Find("h.com", "/api/users/alice"); ok {
		t.Error("삭제된 서브트리가 여전히 조회됨")
	}
	if _, ok := tr.Find("h.com", "/api/orders/alice"); !ok {
		t.Error("형제 노드까지 같이 지워짐")
	}
}

// TestDeleteRootEndpoint — "/" 자체가 엔드포인트인 경우, 그 엔드포인트만 지워지고
// 같은 호스트의 다른 엔드포인트(서브트리)는 살아남아야 한다. 루트 노드는 다른 모든
// 자식의 부모이기도 하므로, 여기서 호스트 전체를 지우면 "/" 하나만 지우려다 나머지
// 전부가 함께 사라지는 회귀(실서비스에서 실제로 겪은 데이터 유실)를 막는 테스트.
func TestDeleteRootEndpoint(t *testing.T) {
	tr := NewTree()
	tr.Record("http", "h1.com", "GET", "/", nil, false, "")
	tr.Record("http", "h1.com", "GET", "/m_login.php", nil, false, "")
	tr.Record("http", "h2.com", "GET", "/b", nil, false, "")

	if !tr.Delete("h1.com", "/") {
		t.Fatal("루트 엔드포인트 삭제 실패")
	}
	// Find 는 트리 노드 존재만 보고(라벨/파라미터 탐색용) methods 유무는 안 보므로,
	// "더 이상 스캔 대상(엔드포인트)이 아니다"는 Targets() 로 확인한다.
	for _, tg := range tr.Targets() {
		if tg.Host == "h1.com" && tg.Path == "/" {
			t.Error("삭제한 루트 엔드포인트가 여전히 Targets()에 남아있음")
		}
	}
	if _, ok := tr.Find("h1.com", "/m_login.php"); !ok {
		t.Error("같은 호스트의 다른 엔드포인트까지 지워짐 — 회귀!")
	}
	if _, ok := tr.Find("h2.com", "/b"); !ok {
		t.Error("무관한 호스트까지 지워짐")
	}
}

// TestDeleteRootEndpointCleansUpWhenChildless — "/" 만 있고 다른 자식이 없으면
// 지운 뒤 빈 루트까지 정리해 호스트가 목록에서 사라진다.
func TestDeleteRootEndpointCleansUpWhenChildless(t *testing.T) {
	tr := NewTree()
	tr.Record("http", "h1.com", "GET", "/", nil, false, "")

	if !tr.Delete("h1.com", "/") {
		t.Fatal("루트 엔드포인트 삭제 실패")
	}
	if len(tr.Targets()) != 0 {
		t.Error("삭제 후에도 대상이 남아있음")
	}
}

// TestDeleteRootWhenRootIsNotAnEndpoint — 루트 자체가 엔드포인트가 아니면(자식만 있는
// 경우) path="/" 삭제는 지울 대상이 없으므로 false — 호스트를 통째로 지우지 않는다.
func TestDeleteRootWhenRootIsNotAnEndpoint(t *testing.T) {
	tr := NewTree()
	tr.Record("http", "h1.com", "GET", "/a", nil, false, "")

	if tr.Delete("h1.com", "/") {
		t.Error("루트가 엔드포인트가 아닌데 삭제가 성공(true)함")
	}
	if _, ok := tr.Find("h1.com", "/a"); !ok {
		t.Error("실패한 삭제가 기존 데이터를 건드림")
	}
}

// TestDeleteNotFound — 없는 대상은 false, 아무것도 건드리지 않는다.
func TestDeleteNotFound(t *testing.T) {
	tr := NewTree()
	tr.Record("http", "h.com", "GET", "/a", nil, false, "")

	if tr.Delete("h.com", "/nope") {
		t.Error("없는 경로인데 true 반환")
	}
	if tr.Delete("nope.com", "") {
		t.Error("없는 호스트인데 true 반환")
	}
	if _, ok := tr.Find("h.com", "/a"); !ok {
		t.Error("실패한 삭제가 기존 데이터를 건드림")
	}
}

// TestClear — 전체 초기화는 지워진 개수를 반환하고, 파일도 함께 비워 재시작 후 되살아나지 않는다.
func TestClear(t *testing.T) {
	const fn = "test_clear_ep.json"
	defer os.Remove(fn)

	tr := &Tree{roots: map[string]*node{}, name: fn}
	tr.Record("http", "h1.com", "GET", "/a", nil, false, "")
	tr.Record("http", "h1.com", "POST", "/b", nil, false, "")
	tr.Record("http", "h2.com", "GET", "/c", nil, false, "")

	n := tr.Clear()
	if n != 3 {
		t.Errorf("Clear() = %d, want 3", n)
	}
	if len(tr.Targets()) != 0 {
		t.Error("Clear 후에도 대상이 남아있음")
	}

	// 파일도 비워졌는지 — 새 Tree 로 Load 하면 빈 상태여야 한다(재시작 시뮬레이션).
	tr2 := &Tree{roots: map[string]*node{}, name: fn}
	tr2.Load()
	if len(tr2.Targets()) != 0 {
		t.Error("Clear 가 파일에 반영되지 않아 재시작 시뮬레이션에서 복원됨")
	}
}
