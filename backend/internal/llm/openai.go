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

// OpenAIProvider — OpenAI 호환 Chat Completions API 프로바이더.
// 엔드포인트만 바꾸면 여러 LLM을 커버한다:
//
//	· OpenAI   endpoint=https://api.openai.com/v1        model=gpt-4o-mini
//	· xAI Grok endpoint=https://api.x.ai/v1              model=grok-2
//	· Groq     endpoint=https://api.groq.com/openai/v1   model=llama-3.1-8b-instant
//	· vLLM/LM Studio/Ollama(호환)  endpoint=http://localhost:.../v1
type OpenAIProvider struct {
	APIKey   string
	Model    string
	Endpoint string
	client   *http.Client
}

func NewOpenAI(apiKey, model, endpoint string) *OpenAIProvider {
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1"
	}
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &OpenAIProvider{
		APIKey:   apiKey,
		Model:    model,
		Endpoint: strings.TrimRight(endpoint, "/"),
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (o *OpenAIProvider) Name() string { return "openai" }

func (o *OpenAIProvider) Complete(ctx context.Context, system, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model":           o.Model,
		"temperature":     0,
		"response_format": map[string]any{"type": "json_object"},
		"messages": []any{
			map[string]any{"role": "system", "content": system},
			map[string]any{"role": "user", "content": user},
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", o.Endpoint+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	if o.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.APIKey)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai %d: %s", resp.StatusCode, string(raw))
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if len(out.Choices) > 0 {
		return out.Choices[0].Message.Content, nil
	}
	return "", nil
}
