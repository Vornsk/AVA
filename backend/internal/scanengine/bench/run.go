package bench

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"time"

	"proxypoc/internal/auth"
	"proxypoc/internal/checklist"
	"proxypoc/internal/detector"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/llm"
	"proxypoc/internal/vulnlab"
)

// Reachable — 대상이 응답하는가(기동 여부 프로브). 어떤 HTTP 응답이든 오면 true.
// 자기서명 인증서 대상도 접속만 확인한다.
func Reachable(base string) bool {
	c := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := c.Get(base)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

// StartTarget — 정답셋의 대상을 준비한다.
//
// Handler 가 지정되면 인프로세스(httptest)로 띄운다 — 외부 기동이 필요 없어 항상 측정 가능하다.
// 아니면 Base 를 그대로 쓰고, 반환된 cleanup 은 아무것도 하지 않는다.
// 두 번째 반환값이 false 면 대상이 없다(호출부에서 skip).
func StartTarget(gt GroundTruth) (base string, cleanup func(), ok bool) {
	switch gt.Handler {
	case "":
		if !Reachable(gt.Base) {
			return "", func() {}, false
		}
		return strings.TrimRight(gt.Base, "/"), func() {}, true
	case "vulnlab":
		srv := httptest.NewServer(vulnlab.Handler())
		return srv.URL, srv.Close, true
	default:
		return "", func() {}, false
	}
}

// SeedTargets — 정답셋의 대상 목록을 스캔 대상(endpoints.Target)으로 변환한다.
//
// ★ 크롤을 돌리지 않는다(합의 ①). 정찰 재현율이 스캔 지표를 오염시키지 않게 하려는 것이고,
// 부수적으로 실행이 결정론적이 된다 — 같은 정답셋이면 매번 같은 대상 집합이다.
// endpoints 전역 트리는 건드리지 않는다(파일 영속화 부작용 회피).
func SeedTargets(gt GroundTruth, base string) ([]endpoints.Target, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	out := make([]endpoints.Target, 0, len(gt.Targets))
	for _, t := range gt.Targets {
		methods := t.Methods
		if len(methods) == 0 {
			methods = []string{"GET"}
		}
		var params []endpoints.Param
		for _, p := range t.Params {
			params = append(params, endpoints.Param{Name: p, In: "query", Sample: "1"})
		}
		for _, p := range t.BodyParams {
			params = append(params, endpoints.Param{Name: p, In: "body", Sample: "1"})
		}
		out = append(out, endpoints.Target{
			Scheme: scheme, Host: u.Host, Path: t.Path,
			Methods: methods, Params: params, Auth: t.Auth,
			Source: "spec", // 정답셋 유래 — 라이브니스 검증 면제 등급
		})
	}
	return out, nil
}

// injectorFor — 정답셋의 인증 설정으로 주입기를 만든다. 전역 auth 상태는 건드리지 않는다
// (recon/bench 의 ApplyAuth 와 달리 대상별 격리가 공짜다).
//
// 신원(Identities)을 반드시 같이 싣는다. idor·privesc detector 는 신원이 2개 미만이면
// 조용히 nil 을 반환하므로, 신원을 안 넣으면 접근통제 계열 전체가 측정에서 빠지고
// 그 정답들이 전부 FN 으로 잡혀 재현율이 거짓으로 낮아진다.
func injectorFor(gt GroundTruth) *auth.Injector {
	inj := auth.New()
	if gt.Auth != nil {
		inj.Set(auth.Config{Cookies: gt.Auth.Cookies, Headers: gt.Auth.Headers})
	}
	if len(gt.Identities) > 0 {
		ids := make([]auth.Identity, 0, len(gt.Identities))
		for _, c := range gt.Identities {
			ids = append(ids, auth.Identity{
				Name: c.Name, Cookies: c.Cookies, Headers: c.Headers, Privileged: c.Privileged,
			})
		}
		inj.SetIdentities(ids)
	}
	return inj
}

// ReachableVulns — 이번 실행에 포함된 detector 들이 도달할 수 있는 VulnDef 집합.
// 파괴성 제외 등으로 빠진 detector 의 담당 취약점을 GT 분모에서 빼기 위해 쓴다.
func ReachableVulns(dets []detector.Detector) map[string]bool {
	out := map[string]bool{}
	for _, d := range dets {
		vulns, _ := checklist.MapDetector(d.ID())
		for _, v := range vulns {
			out[v] = true
		}
	}
	return out
}

// RunDetectors — 대상 집합에 detector 를 돌려 발견을 모은다.
//
// scanengine.Start 를 쓰지 않고 detector 를 직접 부른다. 이유가 둘 있다 —
//   - scanengine 은 finding.Add 로 전역 저장소·findings.json 에 쓴다. 벤치가 제품 상태를
//     오염시키면 안 되고, 상대경로 영속화(HANDOFF §4-4) 때문에 테스트 디렉터리에 파일이 남는다.
//   - 벤치는 진행률·일시정지 같은 잡 제어가 필요 없다.
//
// VulnDef 매핑은 scanengine.execute 와 동일하게 checklist.MapDetector 로 붙인다.
//
// ★ 중간에 ctx 가 끝나면 부분 결과가 아니라 에러를 낸다. 잘린 결과로 채점하면 아직 돌지 않은
// detector 의 정답이 전부 FN 으로 잡혀, 벤치가 "재현율이 낮다"고 자신 있게 거짓말한다.
// (실제로 이 하네스의 초기 실행이 10분 타임아웃에 잘려 csrf·cookie-security·http-method·
// dir-indexing 이 통째로 빠진 채 P=100% 를 출력했다. 조용한 절단은 계기판을 못 쓰게 만든다.)
func RunDetectors(ctx context.Context, targets []endpoints.Target, dets []detector.Detector, inj *auth.Injector) ([]Found, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	var out []Found
	for _, d := range dets {
		for _, t := range targets {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("detector %q · 대상 %q 에서 중단됨(%w) — 남은 detector 가 통째로 빠지므로 채점하지 않는다. SCANBENCH_TIMEOUT 을 늘려 재실행할 것",
					d.ID(), t.Path, err)
			}
			for _, f := range d.Detect(ctx, t, client, inj) {
				vd := f.VulnDef
				if vd == "" {
					if vulns, _ := checklist.MapDetector(f.Detector); len(vulns) > 0 {
						vd = vulns[0]
					}
				}
				out = append(out, Found{
					Path: f.Path, Method: f.Method, Param: f.Param,
					VulnDef: vd, Detector: f.Detector, Severity: f.Severity,
					Evidence: f.Evidence, Request: f.Request, Response: f.Response, RespCode: f.RespCode,
					ContentType: f.ContentType,
				})
			}
		}
	}
	return out, nil
}

// Timeout — 한 대상의 전체 detector 실행 예산. SCANBENCH_TIMEOUT 으로 조정한다(예: 45m).
// 기본이 넉넉한 이유: 시간 기반 블라인드 SQLi 는 대상이 실제로 잠들기를 기다리고,
// idor·privesc 는 신원 수만큼 요청을 곱한다. 짧게 잡으면 조용히 잘리는 게 아니라 에러가 난다.
func Timeout() time.Duration {
	if s := os.Getenv("SCANBENCH_TIMEOUT"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
	}
	return 40 * time.Minute
}

// ReviewLLM — 발견마다 LLM 오탐 판정을 붙인다 (FR-3.3).
//
// 제품은 스캔 중 인라인으로 부르지만(scanengine.execute), 판정은 finding 의 순수 함수라
// 스캔을 두 번 돌릴 필요가 없다. 같은 발견 집합에 판정만 얹어 전·후를 비교한다.
//
// ★ 입력은 제품(scanengine.execute)이 넘기는 것과 같은 필드 집합이다. 증적을 빼고 부르면
// 판정 근거가 사라져 전부 uncertain 이 되고, "LLM 이 오탐을 줄이는가"라는 질문 자체가
// 측정되지 않는다. reviewSysPrompt 가 응답 문맥으로 판단하도록 쓰여 있기 때문이다.
func ReviewLLM(ctx context.Context, found []Found) []Found {
	out := make([]Found, len(found))
	copy(out, found)
	for i := range out {
		rr := llm.Review(ctx, llm.ReviewInput{
			Vuln:        out[i].VulnDef,
			Severity:    out[i].Severity,
			Method:      out[i].Method,
			Path:        out[i].Path,
			Param:       out[i].Param,
			Detector:    out[i].Detector,
			Evidence:    out[i].Evidence,
			Request:     out[i].Request,
			Response:    out[i].Response,
			RespCode:    out[i].RespCode,
			ContentType: out[i].ContentType,
		})
		out[i].LLMFP = rr.Verdict == "false_positive"
	}
	return out
}

// SetupLLM — 벤치용 LLM 프로바이더를 환경변수로 지정한다.
//
//	SCANBENCH_LLM=mock|ollama|anthropic|openai  (미설정이면 프로바이더를 건드리지 않는다)
//	SCANBENCH_LLM_MODEL · SCANBENCH_LLM_ENDPOINT · SCANBENCH_LLM_KEY
//
// 테스트 바이너리는 local.config.yaml 을 읽지 않으므로 여기서 명시적으로 꽂는다.
// 제품 기동 경로에는 영향이 없다.
func SetupLLM() string {
	p := os.Getenv("SCANBENCH_LLM")
	if p == "" {
		return ""
	}
	llm.SetProvider(llm.New(p, os.Getenv("SCANBENCH_LLM_MODEL"), os.Getenv("SCANBENCH_LLM_ENDPOINT"), os.Getenv("SCANBENCH_LLM_KEY")))
	return llm.ProviderName()
}

// LLMAvailable — LLM 프로바이더가 설정돼 있는가. 없으면 판정이 전부 uncertain 이라 비교가 무의미하다.
func LLMAvailable() bool {
	n := llm.ProviderName()
	return n != "" && n != "none"
}
