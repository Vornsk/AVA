// 명세 파서 (이슈 #25). 표준 라이브러리 + 이미 의존성에 있는 yaml.v3 만 쓴다 — 새 파서 라이브러리 없음.
//
// ★ 파싱의 절반은 "이건 명세가 아니다"를 판정하는 일이다. SPA 는 없는 경로에도 200 + index.html 을
// 돌려주므로, content-type 과 필수 키(paths / sources)를 확인하지 않으면 HTML 을 명세로 착각한다.
package ingest

import (
	"encoding/json"
	"errors"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	errNotSpec = errors.New("명세 아님(paths 없음)")
	errNotJSON = errors.New("JSON/YAML 아님")
	errHTML    = errors.New("HTML 응답(SPA catch-all)")
)

// openAPIDoc — OpenAPI 3.x / Swagger 2.0 공통 최소 모델.
type openAPIDoc struct {
	OpenAPI  string                          `json:"openapi" yaml:"openapi"`   // 3.x
	Swagger  string                          `json:"swagger" yaml:"swagger"`   // 2.0
	BasePath string                          `json:"basePath" yaml:"basePath"` // 2.0
	Servers  []openAPIServer                 `json:"servers" yaml:"servers"`   // 3.x
	Paths    map[string]map[string]openAPIOp `json:"paths" yaml:"paths"`
}

type openAPIServer struct {
	URL string `json:"url" yaml:"url"`
}

type openAPIOp struct {
	Parameters  []openAPIParam `json:"parameters" yaml:"parameters"`
	RequestBody *openAPIBody   `json:"requestBody" yaml:"requestBody"`
}

type openAPIParam struct {
	Name     string         `json:"name" yaml:"name"`
	In       string         `json:"in" yaml:"in"`
	Required bool           `json:"required" yaml:"required"`
	Type     string         `json:"type" yaml:"type"`     // 2.0
	Schema   *openAPISchema `json:"schema" yaml:"schema"` // 3.x
}

type openAPISchema struct {
	Type       string                    `json:"type" yaml:"type"`
	Required   []string                  `json:"required" yaml:"required"`
	Properties map[string]*openAPISchema `json:"properties" yaml:"properties"`
}

type openAPIBody struct {
	Required bool                        `json:"required" yaml:"required"`
	Content  map[string]openAPIMediaType `json:"content" yaml:"content"`
}

type openAPIMediaType struct {
	Schema *openAPISchema `json:"schema" yaml:"schema"`
}

// goType — 명세 타입을 endpoints.Param.Type 이 쓰는 어휘로. 알 수 없으면 "string".
// (#24 에서 정한 반환 집합 int|bool|uuid|email|string 을 넘지 않는다.)
func (p openAPIParam) goType() string {
	t := p.Type
	if t == "" && p.Schema != nil {
		t = p.Schema.Type
	}
	switch t {
	case "integer", "number":
		return "int"
	case "boolean":
		return "bool"
	}
	return "string"
}

// bodyParams — requestBody 스키마의 최상위 속성을 파라미터로 편다(중첩은 펴지 않는다).
func (o openAPIOp) bodyParams() []openAPIParam {
	if o.RequestBody == nil {
		return nil
	}
	var out []openAPIParam
	for ct, mt := range o.RequestBody.Content {
		if mt.Schema == nil || len(mt.Schema.Properties) == 0 {
			continue
		}
		req := map[string]bool{}
		for _, r := range mt.Schema.Required {
			req[r] = true
		}
		in := "body"
		if strings.Contains(ct, "json") {
			in = "json"
		}
		for name, sch := range mt.Schema.Properties {
			t := ""
			if sch != nil {
				t = sch.Type
			}
			out = append(out, openAPIParam{Name: name, In: in, Required: req[name], Type: t})
		}
		break // 미디어 타입 하나면 충분하다
	}
	return out
}

// basePath — 경로 앞에 붙일 접두사. Swagger 2.0 은 basePath, 3.x 는 servers[0].url 의 경로부.
func (d *openAPIDoc) basePath() string {
	p := d.BasePath
	if p == "" && len(d.Servers) > 0 {
		u := d.Servers[0].URL
		if i := strings.Index(u, "://"); i >= 0 { // 절대 URL 이면 경로부만
			if j := strings.Index(u[i+3:], "/"); j >= 0 {
				u = u[i+3+j:]
			} else {
				u = ""
			}
		}
		p = u
	}
	p = strings.TrimSuffix(p, "/")
	if p == "/" {
		return ""
	}
	return p
}

// parseOpenAPI — 본문을 OpenAPI 3.x / Swagger 2.0 으로 파싱한다.
// content-type 과 필수 키를 함께 확인해 SPA catch-all HTML 을 걸러낸다.
func parseOpenAPI(body, ctype string) (*openAPIDoc, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, errNotSpec
	}
	if looksLikeHTML(trimmed) {
		return nil, errHTML
	}

	var doc openAPIDoc
	switch {
	case isJSON(ctype) || strings.HasPrefix(trimmed, "{"):
		if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
			return nil, errNotJSON
		}
	case isYAML(ctype) || strings.Contains(trimmed, "\npaths:") || strings.HasPrefix(trimmed, "openapi:") || strings.HasPrefix(trimmed, "swagger:"):
		if err := yaml.Unmarshal([]byte(trimmed), &doc); err != nil {
			return nil, errNotJSON
		}
	default:
		return nil, errNotJSON
	}

	if len(doc.Paths) == 0 {
		return nil, errNotSpec
	}
	if doc.OpenAPI == "" && doc.Swagger == "" {
		return nil, errNotSpec // paths 는 있는데 버전 표식이 없다 = 명세로 보기 어렵다
	}
	return &doc, nil
}

// sourceMap — JS 소스맵 최소 모델. sourcesContent 가 있어야 본문에서 경로를 뽑을 수 있다.
type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// SourceFile — 소스맵에서 복원한 원본 파일 하나. 경로와 본문을 짝지어 파일 단위로 분석한다 (이슈 #39).
//
// sources[i] 파일명과 sourcesContent[i] 본문을 붙여 두면 (1) 벤더(node_modules) 파일을
// 프레임워크 라우트 추출에서 제외할 수 있고 (2) 파일명 힌트를 그대로 쓸 수 있다.
// 전부 이어 붙여 정규식 하나만 돌리던 이전 방식은 이 둘을 못 했다.
type SourceFile struct {
	Path    string // sources[i] — 예: webpack:///./src/app/app-routing.module.ts
	Content string // sourcesContent[i] — 없으면 ""
}

// parseSourceMap — 소스맵을 파싱해 (원본 경로, 본문) 짝 목록을 돌려준다.
// sourcesContent 가 없으면 경로만 채운 SourceFile 을 돌려준다(파일명에 힌트가 있다).
func parseSourceMap(body, ctype string) ([]SourceFile, error) {
	trimmed := strings.TrimSpace(body)
	if looksLikeHTML(trimmed) {
		return nil, errHTML
	}
	if !strings.HasPrefix(trimmed, "{") {
		return nil, errNotJSON
	}
	var sm sourceMap
	if err := json.Unmarshal([]byte(trimmed), &sm); err != nil {
		return nil, errNotJSON
	}
	if sm.Version == 0 || len(sm.Sources) == 0 {
		return nil, errNotSpec
	}
	out := make([]SourceFile, 0, len(sm.Sources))
	for i, src := range sm.Sources {
		f := SourceFile{Path: src}
		if i < len(sm.SourcesContent) {
			f.Content = sm.SourcesContent[i]
		}
		out = append(out, f)
	}
	return out, nil
}

func isYAML(ct string) bool {
	l := strings.ToLower(ct)
	return strings.Contains(l, "yaml") || strings.Contains(l, "yml")
}
