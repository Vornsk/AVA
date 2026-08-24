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
// 그래서 두 가지를 한다 —
//   - 응답 메타데이터(Content-Type)를 프롬프트에 실어 보낸다 (finding.ContentType 이 전제).
//   - detector 별로 "이 탐지기가 어떻게 헛발질하는가"를 명시한다.
package llm

import "strings"

// triageRole — 모든 트리아지 프롬프트의 공통 머리.
//
// ★ "triage" 라는 단어를 반드시 포함한다. mock 프로바이더가 이 단어로 작업을 구분한다(mock.go).
// 프롬프트를 조립식으로 바꾸면서 이 단어가 빠지면 mock 이 판단(Judge)으로 오라우팅해
// 트리아지가 조용히 죽는다 — TestTriagePromptAlwaysMarksTriage 가 감시한다.
const triageRole = "You are a security triage assistant for an authorized web assessment. " +
	"An automated scanner produced a finding using a heuristic that can misfire; your job is to catch false positives. " +
	"Given the finding, the reproduction request, and the masked response evidence, decide whether it is a REAL vulnerability or a FALSE POSITIVE."

// triageResponseMeta — 응답 메타데이터 읽는 법. detector 종류와 무관하게 항상 붙는다.
const triageResponseMeta = "Response metadata matters. content_type is the response's media type as the browser saw it. " +
	"A payload that only ever appears in a non-rendering media type (text/plain, application/json, text/csv, application/octet-stream) " +
	"cannot execute in a browser, no matter how raw the reflection looks. " +
	"Only text/html, application/xhtml+xml and image/svg+xml render markup. " +
	"If content_type is empty, do not assume either way — reason from the body instead."

// triageRegulatory — 규제 맥락. 판정을 보수적인 쪽으로 민다.
//
// 방향이 중요하다. 이 도구의 산출물은 KII·전자금융 점검의 제출 증적이 되므로,
// **정탐을 오탐으로 지우는 쪽이 오탐을 남기는 쪽보다 훨씬 비싸다.** 확신이 없으면
// false_positive 가 아니라 uncertain 이어야 한다(사람이 검토하는 HITL 단계가 뒤에 있다).
const triageRegulatory = "This assessment produces evidence for a regulated security audit (Korean KII / electronic-finance checklists), and a human reviews everything you mark. " +
	"Deleting a real finding is far more costly than keeping a false one: answer false_positive ONLY when the evidence positively rules the vulnerability out. " +
	"When the evidence is thin or ambiguous, answer uncertain — never guess false_positive to look decisive."

// triageContract — 출력 계약. 깨지면 파싱 실패로 전건 uncertain 이 된다.
const triageContract = `Reply with ONLY compact JSON: {"verdict":"real|false_positive|uncertain","reason":string,"remediation":string}.`

// triageHints — detector 별 "이 탐지기는 이렇게 헛발질한다" 목록.
//
// 키는 detector.ID(). 없는 detector 는 공통 규칙만 받는다(빈 힌트가 기본값보다 정직하다 —
// 엉뚱한 힌트를 주면 모델이 없는 근거를 지어낸다).
var triageHints = map[string]string{
	// ★ #49 오탐 5건이 전부 여기서 나왔다. Content-Type 규칙을 가장 먼저 못박는다.
	"reflected-input": "This detector reports a reflection whenever the payload appears verbatim in the body and looks like it sits in an executable position. " +
		"It never checks content_type. So: if content_type is not an HTML-rendering type, the reflection cannot execute and this is a FALSE POSITIVE, even though the payload is raw and unencoded. " +
		"It is also a false positive when the value is HTML-encoded (&lt;, &gt;, &quot;) or lands inside a comment, <textarea>, <title> or a plain-text error message.",
	"stored-xss": "Same blind spot as reflected-input: content_type decides whether the stored marker can execute. " +
		"Additionally the marker must come back on a request that did NOT carry it — if the evidence only shows the injecting response, persistence is unproven, so answer uncertain rather than real.",
	"dom-xss": "This is a static source-to-sink guess in JavaScript, not an observed execution. Absence of a sanitizer in the snippet is not proof. " +
		"Unless the evidence shows the tainted value actually reaching the sink, answer uncertain.",

	"sqli":       "A verbatim DBMS error string (ORA-, SQLSTATE, syntax error near, unclosed quotation) confirms the injection point. A generic 500 page with no DB text does not — that is uncertain.",
	"sqli-blind": "The proof is a differential: the true-condition and false-condition responses must differ while an equivalent benign pair does not. If the evidence shows only one response, it is uncertain.",
	"sqli-time": "A single slow response is not proof — networks and cold caches are slow too. The delay must match the requested sleep duration and be reproducible. " +
		"Without a baseline timing in the evidence, answer uncertain.",

	"path-traversal": "The response must contain actual file content (root:x:0:0, [extensions], BEGIN PRIVATE KEY). " +
		"An echo of the traversal string, or a body that merely contains the word the payload asked for, is a FALSE POSITIVE.",
	"cmd-injection": "The evaluated result of the injected command must appear — output that the input itself did not contain. " +
		"If the response merely echoes the payload, it is a false positive.",
	"ssti":           "The template expression must come back EVALUATED (e.g. 7*7 rendered as 49). If the literal expression is echoed unchanged, it is a false positive.",
	"ssi-injection":  "The directive must come back executed, not echoed. An unprocessed <!--#exec --> string in the body is a false positive.",
	"ldap-injection": "An LDAP-specific error or an obviously widened result set is the proof. A normal page is not.",
	"xxe":            "The proof is external-entity content appearing in the response (file content or an out-of-band callback). A parser error alone is uncertain.",

	"open-redirect": "A 3xx with a Location pointing at an external host confirms it. A same-origin Location, a relative path, or a 200 with no Location is a FALSE POSITIVE.",
	"ssrf":          "The proof is evidence the server itself fetched the attacker-supplied target (fetched content, or an internal-only response). A reflected URL string is not proof.",

	"csrf": "A missing anti-CSRF token is only medium confidence on its own. Check the session cookie: SameSite=Lax or Strict already blocks cross-site form POSTs, which makes this a FALSE POSITIVE. " +
		"Also, an endpoint that requires a custom header (X-Requested-With, Authorization) is not CSRF-able from a form.",
	"idor":    "The proof is that two DIFFERENT identities get the same object back. If both responses are a generic error, a login page, or empty, the identities were never really distinguished — that is uncertain, not real.",
	"privesc": "Same caution as idor: identical responses are proof only when the response actually contains privileged content. Two identical 403 or redirect-to-login pages prove nothing.",

	"sensitive-data": "Evidence is masked, so judge the shape and the surrounding context. Sample/placeholder data (000-0000, example.com, 1234-5678-9012-3456, lorem ipsum) in a demo page is a FALSE POSITIVE. " +
		"Real-looking data on an authenticated page is real.",
	"file-upload": "The upload succeeding is not the vulnerability. The proof is that the uploaded file is reachable AND served as executable content — check content_type on the retrieval. " +
		"If the file comes back as application/octet-stream or a download attachment, it is a false positive.",

	// 헤더·메서드 계열은 응답 헤더 자체가 사실이라 오탐 여지가 거의 없다. 그 점을 알려준다.
	"sec-headers":     "This is a direct observation of response headers, not a heuristic. It is a false positive only if the named header is in fact present in the evidence.",
	"cookie-security": "Also a direct header observation. False positive only if the named attribute is actually present on that Set-Cookie line.",
	"http-method":     "The Allow header or a successful non-GET response is the fact. A 405 or 501 in the evidence makes it a false positive.",
	"dir-indexing":    "The body must show an actual index listing (Index of /, parent directory links). A styled 404 or an application page that happens to list items is a false positive.",
}

// reviewPrompt — detector 맥락이 붙은 트리아지 system 프롬프트를 조립한다 (이슈 #54).
// detector 가 비었거나 모르는 값이면 공통 규칙만으로 조립한다(동작은 유지).
func reviewPrompt(detectorID string) string {
	parts := []string{triageRole, triageResponseMeta}
	if hint := triageHints[strings.TrimSpace(detectorID)]; hint != "" {
		parts = append(parts, "About the '"+detectorID+"' detector specifically: "+hint)
	}
	parts = append(parts, triageRegulatory, triageContract)
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
