// 한국어 카탈로그 — 키의 진실원천(en 은 이 키 집합을 강제받는다).
// 값은 기존 하드코딩 문구와 동일하게 유지해 ko UI 를 변형 없이 보존한다.
export const ko = {
  // 사이드바 그룹
  'group.workspace': '작업공간',
  'group.diagnosis': '진단',
  'group.results': '결과',
  'group.intelligence': '인텔리전스',
  'group.admin': '관리',

  // 사이드바 항목
  'nav.overview': '개요',
  'nav.projects': '프로젝트',
  'nav.recon': '정찰',
  'nav.scan': '스캔',
  'nav.findings': '취약점',
  'nav.coverage': '커버리지',
  'nav.report': '리포트',
  'nav.reverify': '이행점검',
  'nav.advisor': '룰 제안',
  'nav.audit': '감사',
  'nav.users': '사용자',
  'sidebar.readonly': '읽기전용',

  // 페이지 헤더(App META) — title 은 기존 영문 유지, subtitle 만 번역 대상
  'page.overview.title': 'Project Workspace',
  'page.overview.subtitle': '진단 대상과 현황 요약',
  'page.projects.title': 'Projects',
  'page.projects.subtitle': '프로젝트 생성·전환 및 접근 관리',
  'page.recon.title': '대상 파악',
  'page.recon.subtitle': '엔드포인트·요청 판단·스코프·인증 현황',
  'page.scan.title': '자동화 진단',
  'page.scan.subtitle': '진단 실행·탐지기·가드레일·페이로드',
  'page.findings.title': '취약점 목록',
  'page.findings.subtitle': '도출된 취약점과 검토 상태 관리',
  'page.coverage.title': '점검 커버리지',
  'page.coverage.subtitle': '점검항목 대비 진단 결과 — 양호·취약·미점검',
  'page.report.title': '도출리스트',
  'page.report.subtitle': '표준 엑셀 양식(11개 컬럼)으로 내보내기',
  'page.reverify.title': '이행점검',
  'page.reverify.subtitle': '조치 여부 재점검 및 스캔 간 변화 비교',
  'page.advisor.title': 'Rule Advisor',
  'page.advisor.subtitle': 'LLM 판단 기록과 룰 추천',
  'page.audit.title': '감사 로그',
  'page.audit.subtitle': '모든 변경 이력 — 누가·언제·무엇을',
  'page.users.title': '사용자 관리',
  'page.users.subtitle': '계정 목록 및 생성 — 리더 전용',

  // 상단바
  'topbar.logout': '로그아웃',
  'topbar.themeToggle': '테마 전환',
  'topbar.langToggle': '언어 전환',

  // 로그인
  'login.user': '사용자',
  'login.password': '비밀번호',
  'login.errInvalid': '아이디 또는 비밀번호가 올바르지 않습니다.',
  'login.errServer': '서버에 연결할 수 없습니다.',
  'login.submit': '로그인',
  'login.submitting': '로그인 중…',
  'login.demoHint': '데모 계정 — leader / leader123 · analyst / analyst123 ',
  'login.demoNote': '(운영 배포 시 반드시 변경)',

  // 개요
  'overview.allSchemes': '전체 스킴',
  'overview.noScans': '아직 실행된 스캔이 없습니다.',
} as const
