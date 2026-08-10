package bundle

import (
	"os"
	"strings"
	"testing"

	"proxypoc/internal/finding"
	"proxypoc/internal/project"
)

func TestExportImportRoundTrip(t *testing.T) {
	project.Reset()
	finding.Reset()
	defer func() {
		project.Reset()
		finding.Reset()
		_ = os.Remove("projects.json")
		_ = os.Remove("findings.json")
	}()

	p := project.Create(project.Project{Name: "acme", Scope: []string{"acme.test"}, Schemes: []string{"전자금융"}, EncCreds: "SECRET-BLOB"})
	finding.Add(finding.Finding{ProjectID: p.ID, Vuln: "XSS", Host: "acme.test", Path: "/x", Status: "확정"})
	finding.Add(finding.Finding{ProjectID: p.ID, Vuln: "헤더", Host: "acme.test", Path: "/y"})

	data, base, err := Export(p.ID)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if base != "acme" {
		t.Errorf("filename base=%q, want acme", base)
	}
	// 인증정보 blob 은 번들에서 제외돼야 한다.
	if strings.Contains(string(data), "SECRET-BLOB") {
		t.Error("번들에 인증정보(EncCreds) 노출됨")
	}

	// 다른 PC 시뮬: import → 새 프로젝트 + findings 복원.
	np, n, err := Import(data)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if n != 2 {
		t.Errorf("import findings=%d, want 2", n)
	}
	if !strings.Contains(np.Name, "imported") {
		t.Errorf("import 프로젝트명=%q, imported 표시 기대", np.Name)
	}
	// 복원 finding 이 새 프로젝트로 귀속 + 상태 보존.
	got := finding.ByProject(np.ID)
	if len(got) != 2 {
		t.Fatalf("복원 finding %d개", len(got))
	}
	var hasConfirmed bool
	for _, f := range got {
		if f.Status == "확정" {
			hasConfirmed = true
		}
	}
	if !hasConfirmed {
		t.Error("복원 시 검토상태(확정) 보존 안 됨")
	}
}

func TestImportRejectsBadFormat(t *testing.T) {
	if _, _, err := Import([]byte(`{"format":"nope"}`)); err != ErrBadFormat {
		t.Errorf("잘못된 포맷이 통과됨: %v", err)
	}
}

func TestExtNormalization(t *testing.T) {
	SetExt("vdp")
	if Ext() != ".vdp" {
		t.Errorf("ext=%q, want .vdp", Ext())
	}
	SetExt(".cgpkg")
}
