package payload

import "testing"

func contains(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}

func TestFindSensitive(t *testing.T) {
	if got := FindSensitive("주민 900101-1234567 노출"); len(got) == 0 || got[0] != "주민등록번호" {
		t.Errorf("RRN detect: %v", got)
	}
	// Luhn 유효 카드(Visa 테스트) → 카드번호 탐지.
	if got := FindSensitive("card 4111-1111-1111-1111"); !contains(got, "카드번호") {
		t.Errorf("valid card detect: %v", got)
	}
	// Luhn 불통과 16자리(주문번호 등) → 카드번호 오탐 없어야 함.
	for _, k := range FindSensitive("order 1234-5678-9012-3456") {
		if k == "카드번호" {
			t.Error("Luhn 불통과 번호가 카드로 오탐됨")
		}
	}
	if got := FindSensitive("여권 M12345678"); len(got) == 0 || got[0] != "여권번호" {
		t.Errorf("passport detect: %v", got)
	}
	if got := FindSensitive("아무 민감정보 없음"); len(got) != 0 {
		t.Errorf("no-match should be empty: %v", got)
	}
}

// TestAccountPrecision — 계좌번호 정밀화(정밀도 2차): 날짜·전화·짧은 코드 오탐 배제, 실계좌는 탐지.
func TestAccountPrecision(t *testing.T) {
	// 오탐이면 안 되는 것들.
	for _, neg := range []string{
		"작성일 2026-08-07 입니다",         // ISO 날짜 (8자리)
		"연락처 02-1234-5678",            // 유선 전화 (10자리, 0시작)
		"휴대폰 010-1234-5678",           // 휴대폰 (11자리, 0시작)
		"버전 1-2-3",                    // 짧은 코드
		"코드 123-456-789",              // 9자리 (자릿수 미달)
	} {
		if contains(FindSensitive(neg), "계좌번호") {
			t.Errorf("계좌 오탐: %q", neg)
		}
	}
	// 실제 계좌번호 형태는 탐지돼야 함.
	for _, pos := range []string{
		"계좌 110-234-567890 입금",  // 12자리
		"1002-123-456789 로 송금",  // 13자리
	} {
		if !contains(FindSensitive(pos), "계좌번호") {
			t.Errorf("계좌 미탐: %q", pos)
		}
	}
}

func TestXSSConfigExtend(t *testing.T) {
	base := len(XSS())
	if base == 0 {
		t.Fatal("builtin XSS payloads should exist")
	}
	SetXSS([]string{"<custom-xss-marker>"})
	got := XSS()
	if len(got) != base+1 {
		t.Errorf("after SetXSS len = %d, want %d", len(got), base+1)
	}
	found := false
	for _, p := range got {
		if p == "<custom-xss-marker>" {
			found = true
		}
	}
	if !found {
		t.Error("custom payload should be present")
	}
}

func TestInfoVersion(t *testing.T) {
	info := Info()
	if info["version"] != Version {
		t.Errorf("Info version = %v, want %v", info["version"], Version)
	}
}
