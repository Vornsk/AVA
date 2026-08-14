package checklist

// Default — 기본 항목표(시드). 문서 §6의 3계층 구조(Detector→VulnDef→CheckItem).
//
// 주요정보통신기반시설(KII) 웹 항목은 「26년 주요정보통신기반시설 기술적 취약점 분석·평가 방법
// 상세가이드」의 **10. 웹(Web) 애플리케이션 취약점**(CI~WM, 21항목)을 원본 그대로 인코딩한다.
// 우리 detector가 커버하는 항목은 VulnDef.Detectors 로 연결되고, 미커버 항목은 빈 배열 →
// 커버리지에서 "미지원(수동)"으로 집계된다.
//
//	· 섹션 3 「웹 서비스」(WEB-01~26)는 서버 설정 하드닝(파일권한·WebDAV·SSI 등)으로
//	  서버 접근이 필요한 config 감사 항목이라 블랙박스 스캐너 대상이 아님 → 여기선 미인코딩.
//	· 전자금융(항목표2)·모바일(§6.2) 원본표는 아직 확보 전이라 대표 항목만 유지.
func Default() Set {
	s := Set{
		Vulns: []VulnDef{
			// ── 자동 탐지기 있음 (우리 detector 커버) ──
			{ID: "vuln.sqli", Name: "SQL 인젝션",
				Desc:      "입력값 검증 미흡으로 악의적 SQL 구문 실행(에러/불린·시간 블라인드)",
				Detectors: []string{"sqli", "sqli-blind", "sqli-time"}, CWE: "CWE-89"},
			{ID: "vuln.xss", Name: "크로스사이트 스크립트(XSS)", // 반사·저장·DOM 3형태
				Desc:      "입력값이 검증 없이 응답에 반사/저장되어 스크립트가 실행됨",
				Detectors: []string{"reflected-input", "stored-xss", "dom-xss"}, CWE: "CWE-79"},
			{ID: "vuln.csrf", Name: "크로스사이트 요청 위조(CSRF)",
				Desc:      "위조 요청 방지 토큰 부재로 사용자 의도와 무관한 요청 강제",
				Detectors: []string{"csrf"}, CWE: "CWE-352"},
			{ID: "vuln.file-upload", Name: "악성 파일 업로드",
				Desc:      "확장자·타입 검증 미흡으로 실행 가능 파일 업로드",
				Detectors: []string{"file-upload"}, CWE: "CWE-434"},
			{ID: "vuln.file-download", Name: "파일 다운로드 / 경로 순회",
				Desc:      "다운로드 경로 검증 미흡으로 경로 순회·시스템 파일 노출",
				Detectors: []string{"path-traversal"}, CWE: "CWE-22"},
			{ID: "vuln.access-control", Name: "접근통제 미흡(권한검증/관리자페이지 노출)",
				Desc:      "인증·권한 검증 미흡으로 타 사용자/상위 권한 자원 접근, 관리자 페이지 노출",
				Detectors: []string{"idor", "privesc"}, CWE: "CWE-639"},
			{ID: "vuln.info-exposure", Name: "정보 누출",
				Desc:      "주민등록번호·카드·계좌 등 민감정보가 응답에 노출됨",
				Detectors: []string{"sensitive-data"}, CWE: "CWE-200"},

			// ── 자동 탐지기 없음 → 미지원(수동). 원본 항목명 유지 ──
			{ID: "vuln.code-injection", Name: "코드 인젝션", Desc: "입력값이 코드/OS 명령으로 해석·실행됨",
				Detectors: []string{"cmd-injection"}, CWE: "CWE-94"},
			{ID: "vuln.dir-indexing", Name: "디렉터리 인덱싱", Desc: "디렉터리 목록이 그대로 노출됨",
				Detectors: []string{"dir-indexing"}, CWE: "CWE-548"},
			{ID: "vuln.error-page", Name: "에러 페이지 적용 미흡", Desc: "에러 페이지로 내부 정보 노출", CWE: "CWE-209"},
			{ID: "vuln.ssrf", Name: "서버사이드 요청 위조(SSRF)", Desc: "서버가 임의 목적지로 요청을 대신 수행",
				Detectors: []string{"ssrf"}, CWE: "CWE-918"},
			{ID: "vuln.weak-password", Name: "약한 비밀번호 정책", Desc: "비밀번호 복잡도·정책 미흡", CWE: "CWE-521"},
			{ID: "vuln.weak-auth", Name: "불충분한 인증 절차", Desc: "인증 우회·미흡", CWE: "CWE-287"},
			{ID: "vuln.weak-pw-recovery", Name: "취약한 비밀번호 복구 절차", Desc: "비밀번호 재설정 로직 취약", CWE: "CWE-640"},
			{ID: "vuln.process-validation", Name: "프로세스 검증 누락", Desc: "업무 흐름·순서 검증 미흡(로직 우회)", CWE: "CWE-841"},
			{ID: "vuln.weak-session", Name: "불충분한 세션 관리", Desc: "세션 고정·만료·재사용 관리 미흡", CWE: "CWE-384"},
			{ID: "vuln.plaintext", Name: "데이터 평문 전송", Desc: "중요정보를 암호화 없이 전송", CWE: "CWE-319"},
			{ID: "vuln.cookie-tampering", Name: "쿠키 변조", Desc: "쿠키 무결성·보안속성 미흡으로 변조 가능",
				Detectors: []string{"cookie-security"}, CWE: "CWE-565"},
			{ID: "vuln.automation", Name: "자동화 공격", Desc: "자동화 요청 차단(캡차·속도제한) 미흡", CWE: "CWE-799"},
			{ID: "vuln.http-method", Name: "불필요한 Method 악용", Desc: "PUT/DELETE/TRACE 등 위험 메소드 허용",
				Detectors: []string{"http-method"}, CWE: "CWE-650"},

			// ── 서버설정(섹션3) 중 스캐너 대상 항목 ──
			{ID: "vuln.weak-tls", Name: "취약한 SSL/TLS 설정",
				Desc:      "구버전 프로토콜·취약 cipher 허용",
				Detectors: []string{"sslscan", "openssl-tls"}, CWE: "CWE-326"},
			// 전자금융 대표 항목용(원본표 확보 전)
			{ID: "vuln.sec-headers", Name: "미흡한 보안 헤더",
				Desc:      "HSTS/CSP/X-Frame-Options 등 보안 응답 헤더 누락",
				Detectors: []string{"sec-headers"}, CWE: "CWE-693"},
			{ID: "vuln.open-redirect", Name: "오픈 리다이렉트",
				Desc:      "리다이렉트 목적지 미검증으로 외부 악성 사이트 유도",
				Detectors: []string{"open-redirect"}, CWE: "CWE-601"},

			// ── 전자금융 애플리케이션 평가기준 전용(2026 안내서) — 자동탐지 미구현(수동/미지원) ──
			{ID: "vuln.xxe", Name: "XML 외부객체 공격(XXE)", Desc: "XML 입력 검증 미흡으로 내부 자원 접근·외부 명령 실행",
				Detectors: []string{"xxe"}, CWE: "CWE-611"},
			{ID: "vuln.ldap-injection", Name: "LDAP 인젝션", Desc: "LDAP 쿼리 입력 검증 미흡으로 데이터 유출·명령 실행",
				Detectors: []string{"ldap-injection"}, CWE: "CWE-90"},
			{ID: "vuln.ssi-injection", Name: "SSI 인젝션", Desc: "서버측 인클루드(SSI) 명령 삽입 실행",
				Detectors: []string{"ssi-injection"}, CWE: "CWE-97"},
			{ID: "vuln.ssti", Name: "서버측 템플릿 인젝션(SSTI)", Desc: "입력이 서버 템플릿 엔진에 해석돼 임의 코드 실행",
				Detectors: []string{"ssti"}, CWE: "CWE-1336"},
			{ID: "vuln.buffer-overflow", Name: "버퍼 오버플로우", Desc: "경계 검사 미흡으로 메모리 손상·프로그램 흐름 조작", CWE: "CWE-120"},
			{ID: "vuln.format-string", Name: "포맷 스트링", Desc: "포맷 인자 검증 미흡으로 메모리 변조·임의 접근", CWE: "CWE-134"},
			{ID: "vuln.txn-security", Name: "전자금융 거래 보안", Desc: "거래 인증수단·무결성·재사용 방지·소유주 검증 등 거래 프로세스 보안(수동)", CWE: ""},
			{ID: "vuln.auth-credential", Name: "인증정보 관리 미흡", Desc: "인증정보 재사용·고정·유추 가능성", CWE: "CWE-287"},
			{ID: "vuln.client-program", Name: "클라이언트 보안프로그램 미흡", Desc: "OS변조 탐지·악성코드 방지·보안프로그램·난독화·안티디버깅·무결성 등 단말 프로그램 보호(수동)", CWE: ""},
			{ID: "vuln.mobile-client", Name: "모바일 단말 보안 미흡", Desc: "단말 저장·메모리·브라우저·소스코드·백그라운드·딥링크 등 모바일 클라이언트 보호(수동)", CWE: ""},
		},

		CheckItems: []CheckItem{
			// ── 주요정보통신기반시설 : 10.웹(Web) 애플리케이션 (상세가이드 원본 CI~WM) ──
			{ID: "CI", Scheme: SchemeKII, Vuln: "vuln.code-injection"},     // 코드 인젝션
			{ID: "SI", Scheme: SchemeKII, Vuln: "vuln.sqli"},               // SQL 인젝션 ✓
			{ID: "DI", Scheme: SchemeKII, Vuln: "vuln.dir-indexing"},       // 디렉터리 인덱싱
			{ID: "EP", Scheme: SchemeKII, Vuln: "vuln.error-page"},         // 에러 페이지 적용 미흡
			{ID: "IL", Scheme: SchemeKII, Vuln: "vuln.info-exposure"},      // 정보 누출 ✓
			{ID: "XS", Scheme: SchemeKII, Vuln: "vuln.xss"},                // 크로스사이트 스크립트 ✓
			{ID: "CF", Scheme: SchemeKII, Vuln: "vuln.csrf"},               // CSRF ✓
			{ID: "SF", Scheme: SchemeKII, Vuln: "vuln.ssrf"},               // SSRF
			{ID: "BF", Scheme: SchemeKII, Vuln: "vuln.weak-password"},      // 약한 비밀번호 정책
			{ID: "IA", Scheme: SchemeKII, Vuln: "vuln.weak-auth"},          // 불충분한 인증 절차
			{ID: "IN", Scheme: SchemeKII, Vuln: "vuln.access-control"},     // 불충분한 권한 검증 ✓
			{ID: "PR", Scheme: SchemeKII, Vuln: "vuln.weak-pw-recovery"},   // 취약한 비밀번호 복구
			{ID: "PV", Scheme: SchemeKII, Vuln: "vuln.process-validation"}, // 프로세스 검증 누락
			{ID: "FU", Scheme: SchemeKII, Vuln: "vuln.file-upload"},        // 악성 파일 업로드 ✓
			{ID: "FD", Scheme: SchemeKII, Vuln: "vuln.file-download"},      // 파일 다운로드 ✓
			{ID: "IS", Scheme: SchemeKII, Vuln: "vuln.weak-session"},       // 불충분한 세션 관리
			{ID: "SN", Scheme: SchemeKII, Vuln: "vuln.plaintext"},          // 데이터 평문 전송
			{ID: "CC", Scheme: SchemeKII, Vuln: "vuln.cookie-tampering"},   // 쿠키 변조
			{ID: "AE", Scheme: SchemeKII, Vuln: "vuln.access-control"},     // 관리자 페이지 노출 ✓
			{ID: "AU", Scheme: SchemeKII, Vuln: "vuln.automation"},         // 자동화 공격
			{ID: "WM", Scheme: SchemeKII, Vuln: "vuln.http-method"},        // 불필요한 Method 악용

			// ── 전자금융기반시설 : 웹·모바일·HTS 애플리케이션 평가기준 (금융보안원 2026 안내서, ID 1~66) ──
			// [전자금융] 거래·단말 프로그램 보안 (1~18)
			{ID: "1", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 거래 인증수단 검증", Vuln: "vuln.txn-security", Risk: risk(5)},
			{ID: "2", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 거래정보 무결성 검증", Vuln: "vuln.txn-security", Risk: risk(5)},
			{ID: "3", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 거래정보 재사용 방지", Vuln: "vuln.txn-security", Risk: risk(5)},
			{ID: "4", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 거래시 소유주 검증", Vuln: "vuln.txn-security", Risk: risk(5)},
			{ID: "5", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 비밀번호 변경 시 본인확인 절차 수행", Vuln: "vuln.weak-auth", Risk: risk(5)},
			{ID: "6", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 비밀번호 변경 시 이전 비밀번호 재사용 방지", Vuln: "vuln.weak-password", Risk: risk(5)},
			{ID: "7", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] OS 변조 탐지 기능 적용", Vuln: "vuln.client-program", Risk: risk(5)},
			{ID: "8", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 악성코드 방지", Vuln: "vuln.client-program", Risk: risk(5)},
			{ID: "9", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 보안프로그램 동작 여부", Vuln: "vuln.client-program", Risk: risk(5)},
			{ID: "10", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 보안프로그램 임의해제 방지", Vuln: "vuln.client-program", Risk: risk(5)},
			{ID: "11", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 프로그램 실행 명령줄 내 중요정보 평문 노출 방지", Vuln: "vuln.client-program", Risk: risk(5)},
			{ID: "12", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] HTS 구동시 실행 파라미터 재사용 방지", Vuln: "vuln.client-program", Risk: risk(5)},
			{ID: "13", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 이용자 입력정보 보호", Vuln: "vuln.client-program", Risk: risk(4)},
			{ID: "14", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 프로그램 무결성 검증", Vuln: "vuln.client-program", Risk: risk(5)},
			{ID: "15", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 소스코드 난독화 적용", Vuln: "vuln.client-program", Risk: risk(4)},
			{ID: "16", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 디버깅 탐지기능 적용", Vuln: "vuln.client-program", Risk: risk(4)},
			{ID: "17", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 보안프로그램 구동시 최신 업데이트 수행", Vuln: "vuln.client-program", Risk: risk(4)},
			{ID: "18", Scheme: SchemeFinance, Control: "전자금융 거래·단말", Label: "[전자금융] 접근매체 발급 시 실명확인 수행", Vuln: "vuln.txn-security", Risk: risk(5)},
			// 애플리케이션 취약점 (19~66)
			{ID: "19", Scheme: SchemeFinance, Control: "애플리케이션", Label: "SQL Injection", Vuln: "vuln.sqli", Risk: risk(5)},         // ✓
			{ID: "20", Scheme: SchemeFinance, Control: "애플리케이션", Label: "악성파일 업로드", Vuln: "vuln.file-upload", Risk: risk(5)},       // ✓
			{ID: "21", Scheme: SchemeFinance, Control: "애플리케이션", Label: "부적절한 이용자 인가", Vuln: "vuln.access-control", Risk: risk(5)}, // ✓
			{ID: "22", Scheme: SchemeFinance, Control: "애플리케이션", Label: "이용자 인증정보 재사용 방지", Vuln: "vuln.auth-credential", Risk: risk(5)},
			{ID: "23", Scheme: SchemeFinance, Control: "애플리케이션", Label: "고정된 인증정보 이용 방지", Vuln: "vuln.auth-credential", Risk: risk(5)},
			{ID: "24", Scheme: SchemeFinance, Control: "애플리케이션", Label: "유추 가능한 인증정보 이용 방지", Vuln: "vuln.auth-credential", Risk: risk(5)},
			{ID: "25", Scheme: SchemeFinance, Control: "애플리케이션", Label: "유추 가능한 초기화 비밀번호 이용 방지", Vuln: "vuln.weak-pw-recovery", Risk: risk(5)},
			{ID: "26", Scheme: SchemeFinance, Control: "애플리케이션", Label: "단말기 내 중요정보 저장 방지", Vuln: "vuln.mobile-client", Risk: risk(5)},
			{ID: "27", Scheme: SchemeFinance, Control: "애플리케이션", Label: "메모리 내 중요정보 노출 방지", Vuln: "vuln.mobile-client", Risk: risk(5)},
			{ID: "28", Scheme: SchemeFinance, Control: "애플리케이션", Label: "파일 다운로드", Vuln: "vuln.file-download", Risk: risk(5)}, // ✓
			{ID: "29", Scheme: SchemeFinance, Control: "애플리케이션", Label: "외부사이트에 의한 시스템 운영정보 노출 여부", Vuln: "vuln.info-exposure", Risk: risk(5)},
			{ID: "30", Scheme: SchemeFinance, Control: "애플리케이션", Label: "유추 가능한 세션ID", Vuln: "vuln.weak-session", Risk: risk(5)},
			{ID: "31", Scheme: SchemeFinance, Control: "애플리케이션", Label: "쿠키변조", Vuln: "vuln.cookie-tampering", Risk: risk(5)},    // ✓
			{ID: "32", Scheme: SchemeFinance, Control: "애플리케이션", Label: "운영체제 명령실행", Vuln: "vuln.code-injection", Risk: risk(5)}, // ✓
			{ID: "33", Scheme: SchemeFinance, Control: "애플리케이션", Label: "XML 외부객체 공격 (XXE)", Vuln: "vuln.xxe", Risk: risk(5)},
			{ID: "34", Scheme: SchemeFinance, Control: "애플리케이션", Label: "리다이렉트 기능을 이용한 피싱 공격", Vuln: "vuln.open-redirect", Risk: risk(4)}, // ✓
			{ID: "35", Scheme: SchemeFinance, Control: "애플리케이션", Label: "LDAP Injection", Vuln: "vuln.ldap-injection", Risk: risk(5)},
			{ID: "36", Scheme: SchemeFinance, Control: "애플리케이션", Label: "SSI Injection", Vuln: "vuln.ssi-injection", Risk: risk(5)},
			{ID: "37", Scheme: SchemeFinance, Control: "애플리케이션", Label: "불충분한 이용자 인증", Vuln: "vuln.weak-auth", Risk: risk(4)},
			{ID: "38", Scheme: SchemeFinance, Control: "애플리케이션", Label: "화면 내 중요정보 평문노출 방지", Vuln: "vuln.info-exposure", Risk: risk(5)},
			{ID: "39", Scheme: SchemeFinance, Control: "애플리케이션", Label: "무제한 요청 차단", Vuln: "vuln.automation", Risk: risk(5)},
			{ID: "40", Scheme: SchemeFinance, Control: "애플리케이션", Label: "버퍼오버플로우 (Buffer Overflow Attack)", Vuln: "vuln.buffer-overflow", Risk: risk(5)},
			{ID: "41", Scheme: SchemeFinance, Control: "애플리케이션", Label: "포맷스트링 (Format String Attack)", Vuln: "vuln.format-string", Risk: risk(5)},
			{ID: "42", Scheme: SchemeFinance, Control: "애플리케이션", Label: "단말기 브라우저 영역 내에서의 중요정보 노출 방지", Vuln: "vuln.mobile-client", Risk: risk(5)},
			{ID: "43", Scheme: SchemeFinance, Control: "애플리케이션", Label: "앱 소스코드 내 운영정보 노출 방지", Vuln: "vuln.mobile-client", Risk: risk(5)},
			{ID: "44", Scheme: SchemeFinance, Control: "애플리케이션", Label: "화면 강제실행에 의한 인증단계 우회 방지", Vuln: "vuln.mobile-client", Risk: risk(5)},
			{ID: "45", Scheme: SchemeFinance, Control: "애플리케이션", Label: "크로스사이트 요청변조 (CSRF)", Vuln: "vuln.csrf", Risk: risk(4)},    // ✓
			{ID: "46", Scheme: SchemeFinance, Control: "애플리케이션", Label: "디렉토리 목록 노출 방지", Vuln: "vuln.dir-indexing", Risk: risk(4)}, // ✓
			{ID: "47", Scheme: SchemeFinance, Control: "애플리케이션", Label: "서버 인증서 무결성 검증", Vuln: "vuln.weak-tls", Risk: risk(3)},     // ✓
			{ID: "48", Scheme: SchemeFinance, Control: "애플리케이션", Label: "시스템 운영정보 노출 방지", Vuln: "vuln.error-page", Risk: risk(4)},
			{ID: "49", Scheme: SchemeFinance, Control: "애플리케이션", Label: "인증 오류 횟수 제한기능 제공", Vuln: "vuln.weak-auth", Risk: risk(3)},
			{ID: "50", Scheme: SchemeFinance, Control: "애플리케이션", Label: "세션종료 설정", Vuln: "vuln.weak-session", Risk: risk(4)},
			{ID: "51", Scheme: SchemeFinance, Control: "애플리케이션", Label: "취약한 HTTPS 프로토콜 이용 제한", Vuln: "vuln.weak-tls", Risk: risk(3)},   // ✓
			{ID: "52", Scheme: SchemeFinance, Control: "애플리케이션", Label: "취약한 HTTPS 암호 알고리즘 이용", Vuln: "vuln.weak-tls", Risk: risk(3)},   // ✓
			{ID: "53", Scheme: SchemeFinance, Control: "애플리케이션", Label: "취약한 HTTPS 컴포넌트 제거", Vuln: "vuln.weak-tls", Risk: risk(3)},      // ✓
			{ID: "54", Scheme: SchemeFinance, Control: "애플리케이션", Label: "취약한 HTTPS 재협상 차단", Vuln: "vuln.weak-tls", Risk: risk(2)},       // ✓
			{ID: "55", Scheme: SchemeFinance, Control: "애플리케이션", Label: "불필요한 웹 메서드 차단", Vuln: "vuln.http-method", Risk: risk(1)},       // ✓
			{ID: "56", Scheme: SchemeFinance, Control: "애플리케이션", Label: "관리자 페이지 접근 통제 여부", Vuln: "vuln.access-control", Risk: risk(4)}, // ✓
			{ID: "57", Scheme: SchemeFinance, Control: "애플리케이션", Label: "불필요한 파일 노출 여부", Vuln: "vuln.info-exposure", Risk: risk(4)},
			{ID: "58", Scheme: SchemeFinance, Control: "애플리케이션", Label: "크로스 사이트 스크립팅 (XSS)", Vuln: "vuln.xss", Risk: risk(4)}, // ✓
			{ID: "59", Scheme: SchemeFinance, Control: "애플리케이션", Label: "디버그 로그 내 중요정보 노출 방지", Vuln: "vuln.info-exposure", Risk: risk(5)},
			{ID: "60", Scheme: SchemeFinance, Control: "애플리케이션", Label: "백그라운드 화면 보호", Vuln: "vuln.mobile-client", Risk: risk(3)},
			{ID: "61", Scheme: SchemeFinance, Control: "애플리케이션", Label: "서버 사이드 요청 위조 (SSRF)", Vuln: "vuln.ssrf", Risk: risk(4)}, // ✓
			{ID: "62", Scheme: SchemeFinance, Control: "애플리케이션", Label: "세션정보 재사용 제한 여부", Vuln: "vuln.weak-session", Risk: risk(3)},
			{ID: "63", Scheme: SchemeFinance, Control: "애플리케이션", Label: "인증수단 소유자 검증", Vuln: "vuln.txn-security", Risk: risk(5)},
			{ID: "64", Scheme: SchemeFinance, Control: "애플리케이션", Label: "모바일 DeepLink 도용 제한 여부", Vuln: "vuln.mobile-client", Risk: risk(5)},
			{ID: "65", Scheme: SchemeFinance, Control: "애플리케이션", Label: "통신구간 암호화 적용", Vuln: "vuln.plaintext", Risk: risk(5)},
			{ID: "66", Scheme: SchemeFinance, Control: "애플리케이션", Label: "서버 사이드 템플릿 인젝션(SSTI)", Vuln: "vuln.ssti", Risk: risk(5)},

			// ── 모바일 (§6.2, 원본표 확보 전 — 인터페이스 수용만) ──
			{ID: "MOB-01", Scheme: SchemeMobile, Vuln: "vuln.info-exposure"},
		},
	}
	applyEn(s.Vulns) // 영문 로케일 주입 (리포트 en 산출, #18)
	return s
}

// vulnEn — VulnDef 영문 이름/설명 (id → {name_en, desc_en}). 표준 보안 용어 위주.
// ⚠️ 번역 검수 대상: 규제 제출용 산출물이면 보안 담당 확인 권장(#18).
var vulnEn = map[string][2]string{
	"vuln.sqli":               {"SQL Injection", "Malicious SQL executed via insufficient input validation (error / boolean / time-based blind)"},
	"vuln.xss":                {"Cross-Site Scripting (XSS)", "Unvalidated input is reflected/stored in the response and executed as script"},
	"vuln.csrf":               {"Cross-Site Request Forgery (CSRF)", "Missing anti-forgery token lets attackers force requests without user intent"},
	"vuln.file-upload":        {"Malicious File Upload", "Executable files can be uploaded due to weak extension/type validation"},
	"vuln.file-download":      {"File Download / Path Traversal", "Weak download-path validation enables path traversal and system-file exposure"},
	"vuln.access-control":     {"Broken Access Control (authorization / admin page exposure)", "Weak authN/authZ allows access to other users' or higher-privilege resources and exposes admin pages"},
	"vuln.info-exposure":      {"Information Exposure", "Sensitive data (resident registration numbers, cards, accounts) exposed in responses"},
	"vuln.code-injection":     {"Code Injection", "Input is interpreted and executed as code / OS commands"},
	"vuln.dir-indexing":       {"Directory Indexing", "Directory listing is exposed"},
	"vuln.error-page":         {"Improper Error Page Handling", "Internal information is leaked through error pages"},
	"vuln.ssrf":               {"Server-Side Request Forgery (SSRF)", "The server issues requests to arbitrary destinations on the attacker's behalf"},
	"vuln.weak-password":      {"Weak Password Policy", "Insufficient password complexity/policy"},
	"vuln.weak-auth":          {"Insufficient Authentication", "Authentication bypass or weakness"},
	"vuln.weak-pw-recovery":   {"Weak Password Recovery", "Vulnerable password-reset logic"},
	"vuln.process-validation": {"Missing Process Validation", "Weak validation of business flow/sequence (logic bypass)"},
	"vuln.weak-session":       {"Insufficient Session Management", "Weak handling of session fixation, expiry, and reuse"},
	"vuln.plaintext":          {"Cleartext Data Transmission", "Sensitive data transmitted without encryption"},
	"vuln.cookie-tampering":   {"Cookie Tampering", "Cookies can be tampered with due to weak integrity/security attributes"},
	"vuln.automation":         {"Automation Attack", "Insufficient blocking of automated requests (CAPTCHA / rate limiting)"},
	"vuln.http-method":        {"Dangerous HTTP Method Abuse", "Dangerous methods such as PUT/DELETE/TRACE are allowed"},
	"vuln.weak-tls":           {"Weak SSL/TLS Configuration", "Outdated protocols and weak ciphers are allowed"},
	"vuln.sec-headers":        {"Missing Security Headers", "Security response headers such as HSTS/CSP/X-Frame-Options are missing"},
	"vuln.open-redirect":      {"Open Redirect", "Unvalidated redirect destination lures users to external malicious sites"},
	"vuln.xxe":                {"XML External Entity (XXE)", "Weak XML input validation enables internal-resource access and external command execution"},
	"vuln.ldap-injection":     {"LDAP Injection", "Weak LDAP query validation enables data leakage and command execution"},
	"vuln.ssi-injection":      {"SSI Injection", "Server-Side Includes (SSI) command injection and execution"},
	"vuln.ssti":               {"Server-Side Template Injection (SSTI)", "Input is evaluated by the server template engine, enabling arbitrary code execution"},
	"vuln.buffer-overflow":    {"Buffer Overflow", "Weak bounds checking causes memory corruption and control-flow manipulation"},
	"vuln.format-string":      {"Format String", "Weak format-argument validation enables memory corruption and arbitrary access"},
	"vuln.txn-security":       {"E-Finance Transaction Security", "Transaction-process security — authentication means, integrity, replay prevention, owner verification (manual)"},
	"vuln.auth-credential":    {"Improper Credential Management", "Credentials can be reused, fixed, or guessed"},
	"vuln.client-program":     {"Insufficient Client Security Program", "Endpoint protection — OS-tampering detection, anti-malware, security program, obfuscation, anti-debugging, integrity (manual)"},
	"vuln.mobile-client":      {"Insufficient Mobile Client Security", "Mobile client protection — device storage, memory, browser, source code, background, deep links (manual)"},
}

// applyEn — vulnEn 을 VulnDef 슬라이스에 주입.
func applyEn(vulns []VulnDef) {
	for i := range vulns {
		if en, ok := vulnEn[vulns[i].ID]; ok {
			vulns[i].NameEn, vulns[i].DescEn = en[0], en[1]
		}
	}
}
