package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AnthropicProvider — 실제 Claude(Anthropic Messages API) 프로바이더.
// config의 llm.api_key 가 있을 때 사용. (키 없으면 mock 사용)
// temperature 0 로 결정론성 확보(§7 FR-7.3). 응답은 compact JSON verdict.
type AnthropicProvider struct {
	APIKey   string
	Model    string
	Endpoint string
	client   *http.Client
}

func NewAnthropic(apiKey, model, endpoint string) *AnthropicProvider {
	if endpoint == "" {
		endpoint = "https://api.anthropic.com/v1/messages"
	}
	if model == "" {
		model = "claude-haiku-4-5-20251001" // 판단용 소형·고속 모델
	}
	return &AnthropicProvider{
		APIKey:   apiKey,
		Model:    model,
		Endpoint: endpoint,
		client:   &http.Client{Timeout: 60 * time.Second},
	}
}

func (a *AnthropicProvider) Name() string { return "anthropic" }

func (a *AnthropicProvider) Complete(ctx context.Context, system, user string) (string, error) {
	// sampling 파라미터(temperature/top_p/top_k)는 Opus 4.7 이후 모델에서 제거돼
	// 전송하면 400이 된다. 결정론성은 llm.Judge의 시그니처 캐시가 담당한다.
	body, _ := json.Marshal(map[string]any{
		"model":      a.Model,
		"max_tokens": 2048,
		"system":     system,
		"messages":   []any{map[string]any{"role": "user", "content": user}},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", a.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", a.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic %d: %s", resp.StatusCode, string(raw))
	}

	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	// thinking이 켜진 모델은 첫 블록이 thinking이다. text 블록만 고른다.
	for _, c := range out.Content {
		if c.Type == "text" && strings.TrimSpace(c.Text) != "" {
			return c.Text, nil
		}
	}
	return "", nil
}

func extractJSON(s string) string {
	i := strings.Index(s, "{")
	j := strings.LastIndex(s, "}")
	if i >= 0 && j > i {
		return s[i : j+1]
	}
	return s
}
