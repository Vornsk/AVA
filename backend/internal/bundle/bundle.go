// Package bundle — 프로젝트 산출물의 네이티브 포맷 export/import (§5.1 FR-1.6).
// 국내 DRM 솔루션이 확장자 기반으로 xlsx/pdf 등을 자동 암호화·패키징해 PC 간 공유가 깨진다.
// 이를 피하려고 프로젝트(메타+findings)를 사용자 지정 확장자의 네이티브 파일로 저장한다.
// 표준 xlsx export 는 온디맨드(report 패키지)로 별도 제공한다.
package bundle

import (
	"encoding/json"
	"errors"
	"strings"

	"proxypoc/internal/finding"
	"proxypoc/internal/project"
)

// FormatID — 번들 식별자(import 시 검증).
const FormatID = "cyberguard-project"

// Bundle — 네이티브 프로젝트 파일 구조.
type Bundle struct {
	Format   string            `json:"format"`
	Version  int               `json:"version"`
	Project  project.Project   `json:"project"`
	Findings []finding.Finding `json:"findings"`
}

var (
	ErrNotFound  = errors.New("project 없음")
	ErrBadFormat = errors.New("번들 포맷이 아님")
)

// 사용자 지정 확장자 (FR-1.6 DRM 비간섭). 기동 시 config 로 설정.
var ext = ".cgpkg"

// SetExt — 산출물 네이티브 확장자 설정.
func SetExt(e string) {
	if e != "" {
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		ext = e
	}
}

// Ext — 현재 네이티브 확장자.
func Ext() string { return ext }

// Export — 프로젝트를 네이티브 번들 바이트 + 파일명 base 로. 인증정보(EncCreds)는 서버 키에
// 종속돼 이식 불가하므로 제외한다(대상 PC 에서 재입력).
func Export(pid string) (data []byte, filenameBase string, err error) {
	p, ok := project.Get(pid)
	if !ok {
		return nil, "", ErrNotFound
	}
	p.EncCreds = "" // 인증정보 제외 (보안 + 이식성)
	b := Bundle{Format: FormatID, Version: 1, Project: p, Findings: finding.ByProject(pid)}
	data, err = json.MarshalIndent(b, "", "  ")
	return data, sanitize(p.Name), err
}

// Import — 네이티브 번들을 읽어 새 프로젝트 + findings 로 복원한다. 새 프로젝트 + finding 수 반환.
func Import(data []byte) (project.Project, int, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil || b.Format != FormatID {
		return project.Project{}, 0, ErrBadFormat
	}
	np := project.Create(project.Project{
		Name:         b.Project.Name + " (imported)",
		MainURL:      b.Project.MainURL,
		Scope:        b.Project.Scope,
		AllowPaths:   b.Project.AllowPaths,
		ExcludePaths: b.Project.ExcludePaths,
		Schemes:      b.Project.Schemes,
	})
	n := 0
	for _, f := range b.Findings {
		f.ID = ""           // finding.Add 가 새 ID 부여(충돌 방지)
		f.ProjectID = np.ID // 이 PC 의 새 프로젝트로 귀속
		finding.Add(f)      // 상태·검토자·§6 태그는 보존
		n++
	}
	return np, n, nil
}

func sanitize(s string) string {
	repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	out := repl.Replace(s)
	if out == "" {
		out = "project"
	}
	return out
}
