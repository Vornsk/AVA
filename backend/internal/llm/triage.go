// 오탐 트리아지 프롬프트 조립 (이슈 #54) — detector 별 맥락을 자동으로 붙인다.
//
// 왜 필요한가: 트리아지 프롬프트가 detector 종류와 무관하게 하나였다. 그래서 detector 가
// 가진 맹점을 트리아지도 똑같이 갖는다 — 서로의 실수를 잡아주지 못한다.
//
// #49 벤치 실측이 이걸 정확히 보여줬다. 오탐 5건이 전부 `reflected-input` 에서 나왔고
// 원인은 하나다: **응답 Content-Type 을 보지 않는다.** `text/plain` 응답에 반사된 입력은
// 브라우저가 실행하지 않으므로 XSS 가 아닌데, detector 도 트리아지도 그 사실을 안 본다.
// (docs/scan-groundtruth/README.md 베이스라인 절)
//
// ★ 프롬프트 골격에 이유가 있다 — 실측으로 얻은 것이다.
//
//	첫 판본은 detector 별 힌트를 "이 탐지기는 이렇게 헛발질한다"로만 썼다. 오탐 조건만
//	나열하고 정탐 조건을 안 적었더니 qwen2.5:3b 가 reflected-input 을 통째로 오탐 처리했다
//	— 오탐 3건을 걸러내는 대신 **정탐 6건을 지웠다**(재현율 100% → 68.8%).
//	판단 프롬프트가 겪은 실패(main e317d97: 기준 없이 쓰니 전건 차단)와 같은 모양이다.
//
//	그래서 모든 힌트를 **REAL 조건 · FALSE POSITIVE 조건 대칭**으로 쓰고, 기본 방향을
//	명시하고, 예시를 붙인다. 힌트를 고치거나 추가할 때 이 대칭을 깨지 말 것
//	(TestTriageHintsAreSymmetric 이 강제한다).
package llm

import "strings"

// triageRole — 공통 머리 + 판정 기준 + 기본 방향.
//
// ★ "triage" 라는 단어를 반드시 포함한다. mock 프로바이더가 이 단어로 작업을 구분한다(mock.go).
// 프롬프트를 조립식으로 바꾸면서 이 단어가 빠지면 mock 이 판단(Judge)으로 오라우팅해
// 트리아지가 조용히 죽는다 — TestTriagePromptAlwaysMarksTriage 가 감시한다.
const triageRole = `You are a security triage assistant for an authorized web assessment. An automated scanner produced a finding using a heuristic that can misfire. You decide, from the evidence, which of three answers is right.

real — the evidence positively shows the vulnerability: the injected payload came back in a form the browser or server would act on, an error or data leak proves the flaw, or two identities demonstrably saw the same protected object.

false_positive — the evidence positively RULES OUT the vulnerability: something concrete in the response makes exploitation impossible (a non-rendering content type, HTML encoding, a non-executing container, a same-origin redirect, a missing side effect).

uncertain — the evidence is thin, truncated, or ambiguous. This is the honest answer whenever you would otherwise be guessing.

Default to real when the scanner's own condition is met and nothing in the evidence refutes it. You are looking for a REASON to overturn the finding, not for permission to keep it.`

// triageResponseMeta — 응답 메타데이터 읽는 법. 양방향으로 쓴다(한쪽만 쓰면 그쪽으로 쏠린다).
const triageResponseMeta = `Reading content_type — the response's media type as the browser saw it:
  text/html, application/xhtml+xml, image/svg+xml render markup. An unencoded payload here CAN execute → real.
  text/plain, application/json, text/csv, application/octet-stream do NOT render markup. A payload here cannot execute in a browser no matter how raw it looks → false_positive for XSS-family findings.
  empty or absent → no signal. Reason from the body alone and prefer real/uncertain over false_positive.`

// triageRegulatory — 규제 맥락. 판정을 보수적인 쪽(= 지우지 않는 쪽)으로 민다.
//
// 방향이 중요하다. 산출물은 KII·전자금융 점검의 제출 증적이 되고 뒤에 사람 검토(HITL)가 있으므로,
// **정탐을 오탐으로 지우는 쪽이 오탐을 남기는 쪽보다 훨씬 비싸다.**
const triageRegulatory = `This assessment produces evidence for a regulated security audit (Korean KII / electronic-finance checklists) and a human reviews every finding you mark. Deleting a real finding is far more costly than keeping a false one: a false positive costs a reviewer one minute, a deleted true positive ships a vulnerability. Answer false_positive ONLY when you can name the specific fact in the evidence that rules the vulnerability out. If you cannot name it, answer uncertain — never false_positive.`

// triageExamples — 정탐이 먼저 오는 예시. 오탐 예시만 주면 모델이 오탐 쪽으로 쏠린다.
const triageExamples = `Examples:
  detector=reflected-input content_type=text/html response=<h1>hi <script>alert(1)</script></h1>
    -> {"verdict":"real","reason":"unencoded payload in a rendered HTML body","remediation":"contextual output encoding"}
  detector=reflected-input content_type=text/plain response=<script>alert(1)</script>
    -> {"verdict":"false_positive","reason":"text/plain is not rendered as markup, so it cannot execute","remediation":"none required"}
  detector=sqli content_type=text/html response=HTTP 500 Internal Server Error
    -> {"verdict":"uncertain","reason":"a generic 500 is not a DB error string","remediation":"retry with error-based probes"}`

// triageContract — 출력 계약. 깨지면 파싱 실패로 전건 uncertain 이 된다.
const triageContract = `Reply with ONLY compact JSON: {"verdict":"real|false_positive|uncertain","reason":string,"remediation":string}.`

// triageHints — detector 별 판정 기준.
//
// ★ 반드시 "REAL when …" 과 "FALSE POSITIVE when …" 을 모두 담는다. 한쪽만 쓰면 작은 모델이
// 그쪽으로 쏠린다(위 패키지 주석의 실측). 키는 detector.ID() — 없는 detector 는 공통 규칙만 받는다.
var triageHints = map[string]string{
	// ★ #49 오탐 5건이 전부 여기서 나왔다. content_type 규칙을 양방향으로 못박는다.
	"reflected-input": "REAL when content_type renders markup AND the payload came back unencoded in an executable position. " +
		"FALSE POSITIVE when content_type does not render markup, or the payload is HTML-encoded (&lt; &gt; &quot;), or it sits inside a comment, <textarea> or <title>. " +
		"This detector does not check content_type itself, so that check is yours — but a rendered HTML reflection is a genuine finding, not a suspect one.",
	"stored-xss": "REAL when the marker comes back on a request that did NOT carry it AND content_type renders markup — that proves persistence plus executability. " +
		"FALSE POSITIVE when content_type does not render markup. UNCERTAIN when the evidence only shows the injecting response, since persistence is then unproven.",
	"dom-xss": "REAL when the evidence shows the tainted value actually reaching the sink. " +
		"UNCERTAIN when it only shows a source and a sink in the same script — this detector is a static guess, not an observed execution. " +
		"FALSE POSITIVE when the snippet shows the value being sanitized or hard-coded.",

	"sqli": "REAL when a verbatim DBMS error appears (ORA-, SQLSTATE, syntax error near, unclosed quotation). " +
		"UNCERTAIN for a generic 500 with no DB text. FALSE POSITIVE when the response is a normal page or a validation message.",
	"sqli-blind": "REAL when the true-condition and false-condition responses differ while an equivalent benign pair does not. " +
		"UNCERTAIN when the evidence shows only one response. FALSE POSITIVE when both conditions return byte-identical pages.",
	"sqli-time": "REAL when the delay matches the requested sleep duration and a baseline timing is present. " +
		"UNCERTAIN for a single slow response with no baseline — networks and cold caches are slow too. FALSE POSITIVE when the timing is unrelated to the injected duration.",

	"path-traversal": "REAL when the response carries actual file content (root:x:0:0, [extensions], BEGIN PRIVATE KEY). " +
		"FALSE POSITIVE when it only echoes the traversal string, or merely contains the word the payload asked for.",
	"cmd-injection": "REAL when output the input did not contain appears — the command actually ran. " +
		"FALSE POSITIVE when the response only echoes the payload.",
	"ssti":           "REAL when the template expression comes back EVALUATED (7*7 rendered as 49). FALSE POSITIVE when the literal expression is echoed unchanged.",
	"ssi-injection":  "REAL when the directive comes back executed. FALSE POSITIVE when an unprocessed <!--#exec --> string sits in the body.",
	"ldap-injection": "REAL when an LDAP-specific error or an obviously widened result set appears. FALSE POSITIVE on a normal page or a generic validation error.",
	"xxe": "REAL when external-entity content appears in the response (file content or an out-of-band callback). " +
		"UNCERTAIN on a bare parser error. FALSE POSITIVE when entities are rejected outright.",

	"open-redirect": "REAL when a 3xx Location points at an external host. " +
		"FALSE POSITIVE on a same-origin Location, a relative path, or a 200 with no Location at all.",
	"ssrf": "REAL when the evidence shows the server itself fetched the attacker-supplied target (fetched content, or an internal-only response). " +
		"FALSE POSITIVE when the URL is merely reflected back as a string.",

	"csrf": "REAL when a state-changing endpoint accepts a cross-site form POST with no token and no SameSite protection. " +
		"FALSE POSITIVE when the session cookie is SameSite=Lax or Strict, or the endpoint requires a custom header (X-Requested-With, Authorization) that a form cannot send. " +
		"A missing token alone is medium confidence — say uncertain if the cookie attributes are not in the evidence.",
	"idor": "REAL when two DIFFERENT identities get the same protected object back and the response actually contains that object. " +
		"UNCERTAIN when both responses are a generic error, a login page, or empty — the identities were never really distinguished.",
	"privesc": "REAL when a low-privilege identity receives the same privileged CONTENT as the admin identity. " +
		"UNCERTAIN when both responses are 403 or a redirect to login — identical denials prove nothing.",

	"sensitive-data": "REAL when real-looking personal or financial data appears, especially on an authenticated page. Evidence is masked, so judge shape and context, not the literal characters. " +
		"FALSE POSITIVE for obvious sample or placeholder data (000-0000, example.com, 1234-5678-9012-3456, lorem ipsum) on a demo page.",
	"file-upload": "REAL when the uploaded file is retrievable AND served as executable content. " +
		"FALSE POSITIVE when it comes back as application/octet-stream or a download attachment. A successful upload by itself is not the vulnerability — say uncertain if retrieval is not in the evidence.",

	// 헤더·메서드 계열은 응답 헤더 자체가 사실이라 오탐 여지가 거의 없다. 그 점을 분명히 한다.
	"sec-headers": "This is a direct observation of response headers, not a heuristic — REAL by default. " +
		"FALSE POSITIVE only if the named header is in fact present in the evidence.",
	"cookie-security": "Also a direct header observation — REAL by default. " +
		"FALSE POSITIVE only if the named attribute is actually present on that Set-Cookie line.",
	"http-method": "REAL when the Allow header or a successful non-GET response shows the method is enabled. FALSE POSITIVE on a 405 or 501.",
	"dir-indexing": "REAL when the body shows an actual index listing (Index of /, parent-directory links). " +
		"FALSE POSITIVE for a styled 404 or an application page that merely lists items.",
}

// reviewPrompt — detector 맥락이 붙은 트리아지 system 프롬프트를 조립한다 (이슈 #54).
// detector 가 비었거나 모르는 값이면 공통 규칙만으로 조립한다(동작은 유지).
func reviewPrompt(detectorID string) string {
	parts := []string{triageRole, triageResponseMeta}
	if hint := triageHints[strings.TrimSpace(detectorID)]; hint != "" {
		parts = append(parts, "For the '"+detectorID+"' detector specifically: "+hint)
	}
	parts = append(parts, triageRegulatory, triageExamples, triageContract)
	return strings.Join(parts, "\n\n")
}

// TriageDetectors — 전용 힌트를 가진 detector id 목록(테스트·문서용).
func TriageDetectors() []string {
	out := make([]string, 0, len(triageHints))
	for id := range triageHints {
		out = append(out, id)
	}
	return out
}
