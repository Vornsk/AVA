// Package proxyengine — goproxy 조립 (mitm-proxy 모듈).
// 스코프 강제·인증주입·판단 스테이지(Rule/LLM)·마스킹·엔드포인트 추출을 훅에 결합.
// 판단 로직 자체는 각 모듈에 있고 여기선 연결만. 스테이지는 config로 구성(FR-2.2).
package proxyengine

import (
	"log"
	"net/http"

	"github.com/elazarl/goproxy"

	"proxypoc/internal/auth"
	"proxypoc/internal/endpoints"
	"proxypoc/internal/llm"
	"proxypoc/internal/masking"
	"proxypoc/internal/rules"
	"proxypoc/internal/scope"
	"proxypoc/internal/traffic"
)

// New: 기본(전역) 스코프·엔드포인트 트리·인증 주입기·트래픽 로그를 쓰는 프록시 (:8080 공유).
func New(stages []string) *goproxy.ProxyHttpServer {
	return NewFor(stages, scope.Default(), endpoints.Default(), auth.Default(), traffic.Default(), "")
}

// NewFor: 주입된 스코프 Enforcer·엔드포인트 Tree·인증 Injector·트래픽 Log 로 동작하는 프록시 (멀티테넌시 §5.1).
// tag 는 로그 접두(테넌트 식별). 판단 파이프라인·마스킹·LLM 은 공유(Phase 2: auth·traffic 도 테넌트별).
func NewFor(stages []string, sc *scope.Enforcer, tr *endpoints.Tree, inj *auth.Injector, tl *traffic.Log, tag string) *goproxy.ProxyHttpServer {
	ruleOn := contains(stages, "rule")
	llmOn := contains(stages, "llm")
	// 공용(전역) 트리를 쓰는 프록시만 캡처 on/off 토글의 영향을 받는다(이슈 #5).
	// 테넌트 전용 트리는 항상 캡처 → 멀티테넌시 격리 유지.
	shared := tr == endpoints.Default()
	if tag != "" {
		tag = "[" + tag + "] "
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// CONNECT(HTTPS 시작): host만으로 스코프 판단 (path 미상).
	proxy.OnRequest().HandleConnectFunc(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			if sc.InScope(scope.HostOnly(host)) {
				return goproxy.MitmConnect, host
			}
			log.Printf("%s[BLOCK] CONNECT %s (스코프 밖)", tag, host)
			return goproxy.RejectConnect, host
		})

	proxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// 스코프 강제 (FR-2.1): host + 경로 허용/제외 종합 판단.
			if ok, reason := sc.Allowed(req.URL.Hostname(), req.URL.Path); !ok {
				log.Printf("%s[BLOCK] %-6s %s (%s)", tag, req.Method, masking.Mask(req.URL.String()), reason)
				return req, goproxy.NewResponse(req,
					goproxy.ContentTypeText, http.StatusForbidden,
					"차단됨: "+reason+"\n")
			}

			maskedURL := masking.Mask(req.URL.String())
			params := endpoints.ExtractParams(req) // 주입 전 원본 파라미터 (FR-2.4)

			// 인증 크롤링 (FR-2.5): 통과 요청에 세션/쿠키·인증헤더 주입 (테넌트별 injector).
			inj.Inject(req)

			authReq := req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != ""

			// 판단 스테이지 (FR-2.2): 구성된 스테이지만 실행.
			verdict, resp := judge(req, maskedURL, params, ruleOn, llmOn)
			if resp != nil {
				return req, resp // 차단됨
			}

			log.Printf("%s[REQ ] %-6s %s", tag, req.Method, maskedURL)
			tl.Record(req.Method, maskedURL)
			// 캡처 off(공용 프록시)면 엔드포인트 기록만 건너뛴다 — 트래픽 로그·통과는 유지(이슈 #5).
			if !shared || captureOn.Load() {
				// scheme+authority(host[:port]) 보존 → 스캔 재요청이 원 스킴·포트로 나감.
				tr.Record(req.URL.Scheme, req.URL.Host, req.Method, req.URL.Path, params, authReq, verdict)
				if shared {
					capturedReqs.Add(1)
				}
			}
			return req, nil
		})

	// 응답 훅: 상태·타입 로그(마스킹).
	proxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp != nil {
				log.Printf("[RESP] %-3d    %s  (%s)", resp.StatusCode,
					masking.Mask(ctx.Req.URL.String()), resp.Header.Get("Content-Type"))
			}
			return resp
		})

	return proxy
}

// judge — 구성된 스테이지로 요청을 판단. 차단이면 (_, resp!=nil), 통과면 (verdict, nil).
func judge(req *http.Request, maskedURL string, params []endpoints.Param, ruleOn, llmOn bool) (string, *http.Response) {
	if ruleOn {
		switch d := rules.Evaluate(req.Method, req.URL.Path); d.Action {
		case "block":
			log.Printf("[RULE] %-6s %s (차단: %s — %s)", req.Method, maskedURL, d.Rule, d.Reason)
			return "", blocked(req, "룰: "+d.Rule+": "+d.Reason)
		case "llm":
			if llmOn {
				return runLLM(req, maskedURL, params, d.Reason)
			}
			return "LLM 스테이지 비활성 — 통과", nil
		default:
			if d.Action == "allow" {
				return "룰 허용: " + d.Rule, nil
			}
		}
		return "", nil
	}
	// Rule 스테이지 off인데 LLM만 on → 상태변경 요청을 직접 LLM 판단.
	if llmOn && isWrite(req.Method) {
		return runLLM(req, maskedURL, params, "상태변경 요청 — LLM 위험 판단")
	}
	return "", nil
}

func runLLM(req *http.Request, maskedURL string, params []endpoints.Param, hint string) (string, *http.Response) {
	v := llm.Judge(req.Context(), llm.JudgeInput{
		Method:      req.Method,
		Path:        endpoints.NormalizePath(req.URL.Path), // 정규화 path로 dedup·캐싱 (FR-2.3)
		ParamKeys:   endpoints.Names(params),
		ContentType: req.Header.Get("Content-Type"),
		Hint:        hint,
	})
	if !v.Allow {
		log.Printf("[LLM ] %-6s %s (차단: %s [%s/%s])", req.Method, maskedURL, v.Reason, v.Provider, v.Model)
		return "", blocked(req, "LLM: "+v.Reason)
	}
	log.Printf("[LLM ] %-6s %s (허용: %s [%s])", req.Method, maskedURL, v.Reason, v.Provider)
	return "LLM 허용: " + v.Reason, nil
}

func blocked(req *http.Request, reason string) *http.Response {
	return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "차단됨("+reason+")\n")
}

func isWrite(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
