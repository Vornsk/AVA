package llm_test

// 이슈 #54 — 트리아지 힌트 키가 실제 detector id 와 붙어 있는지 확인한다.
// 별도 외부 테스트 패키지인 이유: llm 은 어떤 내부 패키지도 import 하지 않는다(의도된 격리).
// detector 를 여기서만 끌어와 오타·이름 변경으로 힌트가 조용히 죽는 것을 막는다.

import (
	"testing"

	"proxypoc/internal/detector"
	"proxypoc/internal/llm"
)

func TestTriageHintsMatchRealDetectorIDs(t *testing.T) {
	real := map[string]bool{}
	for _, d := range detector.Catalog() {
		real[d.ID] = true
	}

	for _, id := range llm.TriageDetectors() {
		if !real[id] {
			t.Errorf("트리아지 힌트 키 %q 에 해당하는 detector 가 없다 — 오타이거나 id 가 바뀌었다(힌트가 조용히 죽는다)", id)
		}
	}

	// 오탐이 실제로 나온 탐지기에는 힌트가 반드시 있어야 한다(#49 베이스라인).
	must := map[string]bool{"reflected-input": false}
	for _, id := range llm.TriageDetectors() {
		if _, ok := must[id]; ok {
			must[id] = true
		}
	}
	for id, has := range must {
		if !has {
			t.Errorf("%q 에 트리아지 힌트가 없다 — #49 오탐 5건이 전부 여기서 나왔다", id)
		}
	}
}
