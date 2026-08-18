// Package bench — 정찰 벤치마크 하네스 (#22).
//
// 목적: 정찰 실행 → 발견 엔드포인트 수집 → ground-truth 대조 → P/R/F1·팽창률 리포트.
// 개선(정규화 v2 #3, 스펙 인제스터 #4, 라이브니스 #5)의 효과/회귀를 숫자로 검증하는 계기판.
//
// ★ 설계 제약 (이슈 #22): 채점용 매칭 키를 제품 endpoints.NormalizePath 에 의존시키지 않는다.
//   #3 가 그 함수를 바꾸면 순환 측정이 되기 때문. 하네스는 아래 Canon() 자체 규칙만 사용하고,
//   제품 정규화 품질은 "트리 팽창률"(제품이 접은 노드 수 대비 하네스 canonical 수)로만 관찰한다.
//   → 이 파일은 endpoints 패키지를 import 하지 않는다(비의존성의 코드적 보장).
package bench

import (
	"regexp"
	"strings"
)

var (
	reUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reNum  = regexp.MustCompile(`^\d+$`)
	// hex 는 실단어 오폴딩을 피하려 16자 이상만 변수로 간주(예: 세션·토큰·해시).
	reHex = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
)

// Canon — 경로를 하네스 자체 규칙으로 canonical 화한다(제품 NormalizePath 비의존).
// 가변 세그먼트(숫자·uuid·hex·date, 그리고 ground-truth 의 {id} 같은 플레이스홀더)를
// 단일 토큰 "{}" 로 접어, 구체 경로(/rest/products/42)와 정답(/rest/products/{id})이 매칭되게 한다.
func Canon(path string) string {
	// 쿼리/프래그먼트 제거.
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	path = strings.Trim(path, "/")
	if path == "" {
		return "/"
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = canonSeg(s)
	}
	return "/" + strings.Join(segs, "/")
}

func canonSeg(s string) string {
	switch {
	case s == "":
		return ""
	case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}"): // GT 플레이스홀더 {id}, {uuid} 등
		return "{}"
	case strings.HasPrefix(s, ":"): // :id 스타일 플레이스홀더
		return "{}"
	case reUUID.MatchString(s):
		return "{}"
	case reDate.MatchString(s):
		return "{}"
	case reNum.MatchString(s):
		return "{}"
	case reHex.MatchString(s):
		return "{}"
	default:
		return s
	}
}

// key — 매칭 단위: "METHOD /canon/path".
func key(method, path string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + Canon(path)
}
