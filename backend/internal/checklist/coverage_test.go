package checklist

import "testing"

func TestCoverageStatuses(t *testing.T) {
	Load(Default())

	// reflected-input: 코드있음+실행+finding / sec-headers: 코드있음 실행X /
	// sslscan: 매핑됐으나 미설치 / (SQLi 등은 detector 매핑 없음 → 수동)
	available := map[string]bool{"reflected-input": true, "sec-headers": true, "sensitive-data": true, "idor": true, "openssl-tls": true}
	ran := map[string]bool{"reflected-input": true}
	findings := map[string]int{"reflected-input": 2}

	rep := Coverage(available, ran, findings)
	if len(rep.Schemes) != 3 {
		t.Fatalf("스킴 %d개, want 3", len(rep.Schemes))
	}

	find := func(id string) ItemStatus {
		for _, sc := range rep.Schemes {
			for _, it := range sc.Items {
				if it.CheckItem.ID == id {
					return it
				}
			}
		}
		t.Fatalf("checkitem %s 없음", id)
		return ItemStatus{}
	}

	if s := find("XS"); s.Status != StatusVulnerable || s.Findings != 2 { // XSS, finding 있음
		t.Errorf("XS = %+v, want 취약/2", s)
	}
	if s := find("21"); s.Status != StatusNotRun { // 부적절한 이용자 인가(idor), 실행 안함 → 미점검
		t.Errorf("전자금융 21 = %s, want 미점검", s.Status)
	}
	// weak-tls는 [sslscan, openssl-tls] 매핑. openssl-tls가 available이므로 미점검.
	if s := find("51"); s.Status != StatusNotRun || !s.Available { // 취약한 HTTPS 프로토콜
		t.Errorf("전자금융 51 = %+v, want 미점검/available(openssl-tls)", s)
	}
	if s := find("SI"); !s.Automatable { // SQL 인젝션, sqli 매핑됨
		t.Errorf("SI = %+v, want 자동가능", s)
	}
	if s := find("CF"); !s.Automatable { // CSRF, csrf 매핑됨
		t.Errorf("CF = %+v, want 자동가능", s)
	}
	// 미커버(수동) 예시: EP 에러 페이지는 detector 없음(CI·SF는 cmd-injection·ssrf 매핑됨).
	if s := find("EP"); s.Status != StatusManual || s.Automatable {
		t.Errorf("EP = %+v, want 수동/자동불가", s)
	}

	// 전자금융 XSS(58)도 같은 detector 로 취약이어야 한다(중복 취약점 공유).
	if s := find("58"); s.Status != StatusVulnerable {
		t.Errorf("전자금융 58(XSS) = %s, want 취약(reflected-input 공유)", s.Status)
	}
}

func TestSchemeAggregates(t *testing.T) {
	Load(Default())
	rep := Coverage(map[string]bool{"reflected-input": true}, nil, map[string]int{"reflected-input": 1})
	for _, sc := range rep.Schemes {
		if sc.Scheme == SchemeKII {
			if sc.Total != 21 { // 10.웹(Web) CI~WM 21항목
				t.Errorf("KII total=%d, want 21", sc.Total)
			}
			if sc.Vulnerable != 1 { // XS(XSS) 하나
				t.Errorf("KII vulnerable=%d, want 1", sc.Vulnerable)
			}
			if sc.Manual != 8 { // 수동 항목(EP/BF/IA/PR/PV/IS/SN/AU) — CI·SF는 cmd-injection·ssrf 매핑됨
				t.Errorf("KII manual=%d, want 8", sc.Manual)
			}
		}
	}
}

func TestCoverageCleanAndNoTool(t *testing.T) {
	Load(Default())
	// dir-indexing 실행됐고 finding 없음 → 점검-이상없음.
	// weak-tls detector(sslscan/openssl-tls) 둘 다 미설치 → 미지원(도구없음).
	rep := Coverage(map[string]bool{"dir-indexing": true}, map[string]bool{"dir-indexing": true}, nil)
	var clean, noTool bool
	for _, sc := range rep.Schemes {
		for _, it := range sc.Items {
			if it.CheckItem.Vuln == "vuln.dir-indexing" && it.Status == StatusClean {
				clean = true
			}
			if it.CheckItem.Vuln == "vuln.weak-tls" && it.Status == StatusNoTool {
				noTool = true
			}
		}
	}
	if !clean {
		t.Error("dir-indexing 실행+무발견 → 점검-이상없음 기대")
	}
	if !noTool {
		t.Error("weak-tls 도구 미설치 → 미지원(도구없음) 기대")
	}
}

func TestMapDetector(t *testing.T) {
	Load(Default())
	SetSelected(nil)
	defer SetSelected(nil)
	vulns, items := MapDetector("reflected-input")
	if len(vulns) != 1 || vulns[0] != "vuln.xss" {
		t.Errorf("vulns=%v, want [vuln.xss]", vulns)
	}
	if len(items) < 2 { // KII-02 + WEB-SER-004
		t.Errorf("items=%v, want ≥2", items)
	}
}

// 스킴 선택 시 커버리지·태깅이 선택 탭으로만 좁혀져야 한다(§3 프로젝트 스킴).
func TestSelectedSchemesFilter(t *testing.T) {
	Load(Default())
	defer SetSelected(nil)

	SetSelected([]Scheme{SchemeFinance})
	rep := Coverage(map[string]bool{"reflected-input": true}, nil, map[string]int{"reflected-input": 1})
	if len(rep.Schemes) != 1 || rep.Schemes[0].Scheme != SchemeFinance {
		t.Fatalf("선택=전자금융인데 커버리지 스킴=%v", rep.Schemes)
	}

	// 태깅도 선택 탭 항목만: reflected-input → 전자금융 58(XSS)만, KII XS 제외.
	_, items := MapDetector("reflected-input")
	if len(items) != 1 || items[0] != "58" {
		t.Errorf("선택 탭 태깅 items=%v, want [58]", items)
	}

	// 선택 해제 → 전체 복귀.
	SetSelected(nil)
	if got := len(Coverage(nil, nil, nil).Schemes); got != 3 {
		t.Errorf("선택 해제 후 스킴=%d, want 3", got)
	}
}
