package llm

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// 이슈 #54 — detector 맥락이 붙은 트리아지 프롬프트.

// userRecorder — 받은 system·user 프롬프트를 기록만 하는 스텁.
type userRecorder struct {
	mu     sync.Mutex
	system []string
	user   []string
	reply  string
}

func (r *userRecorder) Name() string { return "userrec" }

func (r *userRecorder) Complete(_ context.Context, system, user string) (string, error) {
	r.mu.Lock()
	r.system = append(r.system, system)
	r.user = append(r.user, user)
	r.mu.Unlock()
	if r.reply == "" {
		return `{"verdict":"uncertain","reason":"x","remediation":"y"}`, nil
	}
	return r.reply, nil
}

// ★ mock 프로바이더는 system 에 "triage" 가 있어야 오탐검토로 라우팅한다(mock.go).
// 프롬프트를 조립식으로 바꾸면서 이 단어가 빠지면 트리아지가 조용히 죽는다.
func TestTriagePromptAlwaysMarksTriage(t *testing.T) {
	ids := append(TriageDetectors(), "", "  ", "unknown-detector-xyz")
	for _, id := range ids {
		p := reviewPrompt(id)
		if !strings.Contains(p, "triage") {
			t.Errorf("detector %q 프롬프트에 'triage' 없음 — mock 이 판단으로 오라우팅한다", id)
		}
		if !strings.Contains(p, triageContract) {
			t.Errorf("detector %q 프롬프트에 출력 계약 없음 — 파싱 실패로 전건 uncertain 이 된다", id)
		}
		if !strings.Contains(p, "content_type") {
			t.Errorf("detector %q 프롬프트에 응답 메타데이터 규칙 없음", id)
		}
	}
}

// 규제 맥락은 판정을 보수적인 쪽으로 밀어야 한다 — 확신 없으면 false_positive 가 아니라 uncertain.
// 방향이 반대면 트리아지가 정탐을 지운다(벤치의 '정탐 삭제' 열이 이걸 잡는다).
func TestTriagePromptBiasesConservative(t *testing.T) {
	p := reviewPrompt("reflected-input")
	if !strings.Contains(p, "uncertain") {
		t.Error("불확실할 때의 지침이 없다")
	}
	if !strings.Contains(p, "Deleting a real finding is far more costly") {
		t.Error("정탐 삭제 비용이 더 크다는 규제 맥락이 빠졌다")
	}
}

// detector 마다 프롬프트가 실제로 달라야 한다. 같으면 이 이슈가 한 일이 없다.
func TestTriagePromptVariesByDetector(t *testing.T) {
	refl := reviewPrompt("reflected-input")
	csrf := reviewPrompt("csrf")
	unknown := reviewPrompt("nope")

	if refl == csrf {
		t.Fatal("reflected-input 과 csrf 프롬프트가 동일 — detector 맥락이 붙지 않았다")
	}
	if !strings.Contains(refl, "It never checks content_type") {
		t.Error("reflected-input 힌트(#49 오탐 5건의 원인)가 빠졌다")
	}
	if !strings.Contains(csrf, "SameSite") {
		t.Error("csrf 힌트에 SameSite 검증이 없다")
	}
	if strings.Contains(unknown, "About the") {
		t.Error("모르는 detector 에 엉뚱한 힌트를 붙였다 — 없는 근거를 지어내게 만든다")
	}
}

// Review 가 content_type 을 실제로 실어 보내고, detector 별 system 프롬프트를 쓰는가.
func TestReviewSendsContentTypeAndDetectorPrompt(t *testing.T) {
	rec := &userRecorder{}
	SetProvider(rec)
	t.Cleanup(func() { SetProvider(MockProvider{}) })

	Review(context.Background(), ReviewInput{
		Vuln: "vuln.xss", Detector: "reflected-input", Path: "/exec",
		ContentType: "text/plain", Response: "<script>alert(1)</script>",
	})

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.user) != 1 {
		t.Fatalf("호출 %d회", len(rec.user))
	}
	if !strings.Contains(rec.user[0], "content_type=text/plain") {
		t.Errorf("user 프롬프트에 content_type 없음:\n%s", rec.user[0])
	}
	if rec.system[0] != reviewPrompt("reflected-input") {
		t.Error("system 프롬프트가 detector 별 조립본이 아니다")
	}
}

// mock 이 Content-Type 맹점을 벗어났는가 — #49 오탐 5건과 같은 모양.
// ★ 정탐 삭제 금지도 같이 확인한다. 오탐만 줄고 정탐이 지워지면 도구는 나빠진 것이다.
func TestMockTriageUsesContentType(t *testing.T) {
	SetProvider(MockProvider{})
	base := ReviewInput{Vuln: "vuln.xss", Detector: "reflected-input", Path: "/exec",
		Evidence: "페이로드가 실행 가능한 컨텍스트에 인코딩 없이 반사됨",
		Response: "<script>alert(1)</script>"}

	plain := base
	plain.ContentType = "text/plain"
	if v := Review(context.Background(), plain); v.Verdict != "false_positive" {
		t.Errorf("text/plain 반사 verdict = %q, want false_positive (브라우저가 실행 못 한다)", v.Verdict)
	}

	html := base
	html.ContentType = "text/html"
	if v := Review(context.Background(), html); v.Verdict == "false_positive" {
		t.Error("★ text/html 반사를 오탐으로 지웠다 — 정탐 삭제")
	}

	unknown := base // content_type 미상은 판단 근거가 아니다
	if v := Review(context.Background(), unknown); v.Verdict == "false_positive" {
		t.Error("content_type 미상인데 오탐으로 단정했다")
	}
}
