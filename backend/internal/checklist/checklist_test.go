package checklist

import "testing"

// 기본 항목표는 코드에 있는 detector 로만 매핑돼야 한다(허위 매핑 없음).
func TestDefaultValidAgainstRealDetectors(t *testing.T) {
	available := map[string]bool{
		"sec-headers": true, "reflected-input": true, "stored-xss": true, "dom-xss": true, "sensitive-data": true,
		"idor": true, "privesc": true, "sqli": true, "sqli-blind": true, "sqli-time": true, "path-traversal": true,
		"open-redirect": true, "csrf": true, "file-upload": true, "cookie-security": true, "http-method": true, "dir-indexing": true,
		"cmd-injection": true, "ssrf": true, "ssti": true, "xxe": true, "ldap-injection": true, "ssi-injection": true,
		"destructive-demo": true, "sslscan": true, "openssl-tls": true,
	}
	if issues := Validate(available); len(issues) != 0 {
		t.Fatalf("기본 항목표 검증 실패: %v", issues)
	}
}

// Validate 는 미존재 detector·미존재 vuln·중복 id 를 잡아야 한다.
func TestValidateCatchesErrors(t *testing.T) {
	Load(Set{
		Vulns: []VulnDef{
			{ID: "v.a", Detectors: []string{"nope"}},
			{ID: "v.a"}, // 중복
		},
		CheckItems: []CheckItem{
			{ID: "C1", Vuln: "v.a"},
			{ID: "C2", Vuln: "missing"}, // 미존재 vuln
		},
	})
	defer Load(Default())

	issues := Validate(map[string]bool{})
	if len(issues) < 3 {
		t.Errorf("기대: 미존재 detector + 중복 vuln + 미존재 vuln, got %v", issues)
	}
}

// 3계층 연결: CheckItem → VulnDef → detector 가 양방향으로 이어져야 한다.
func TestLayerLinkage(t *testing.T) {
	Load(Default())

	dets := DetectorsFor("XS") // 크로스사이트 스크립트 (반사·저장·DOM)
	if len(dets) != 3 || dets[0] != "reflected-input" || dets[1] != "stored-xss" || dets[2] != "dom-xss" {
		t.Errorf("XS → detectors = %v, want [reflected-input stored-xss dom-xss]", dets)
	}

	// 역방향: reflected-input 은 XSS 를 참조하는 모든 스킴의 항목을 커버.
	items := CheckItemsForDetector("reflected-input")
	if len(items) < 2 { // XS(KII) + WEB-SER-004(전자금융)
		t.Errorf("reflected-input 커버 항목 %d개, want ≥2", len(items))
	}

	// 커버 항목: SI(SQL 인젝션)는 sqli·sqli-blind·sqli-time 매핑됨.
	if d := DetectorsFor("SI"); len(d) != 3 || d[0] != "sqli" || d[2] != "sqli-time" {
		t.Errorf("SI(SQLi) → detectors = %v, want [sqli sqli-blind sqli-time]", d)
	}
	// 커버 항목: CF(CSRF)는 csrf 매핑됨.
	if d := DetectorsFor("CF"); len(d) != 1 || d[0] != "csrf" {
		t.Errorf("CF(CSRF) → detectors = %v, want [csrf]", d)
	}
	// 커버 항목: FU(악성 파일 업로드)는 file-upload 매핑됨.
	if d := DetectorsFor("FU"); len(d) != 1 || d[0] != "file-upload" {
		t.Errorf("FU(파일 업로드) → detectors = %v, want [file-upload]", d)
	}
	// 커버 항목: SF(SSRF)는 ssrf, CI(코드/OS 명령)는 cmd-injection 매핑됨.
	if d := DetectorsFor("SF"); len(d) != 1 || d[0] != "ssrf" {
		t.Errorf("SF(SSRF) → detectors = %v, want [ssrf]", d)
	}
	if d := DetectorsFor("CI"); len(d) != 1 || d[0] != "cmd-injection" {
		t.Errorf("CI(코드 인젝션) → detectors = %v, want [cmd-injection]", d)
	}
	// 미커버 항목: EP(에러 페이지)는 detector 없음(수동).
	if d := DetectorsFor("EP"); len(d) != 0 {
		t.Errorf("EP는 미커버여야 함, got %v", d)
	}
}

func TestSchemes(t *testing.T) {
	Load(Default())
	if got := len(Schemes()); got != 3 {
		t.Errorf("스킴 수=%d, want 3 (KII/전자금융/모바일)", got)
	}
}
