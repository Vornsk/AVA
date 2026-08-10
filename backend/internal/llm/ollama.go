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

// OllamaProvider — 로컬 LLM(Ollama) 프로바이더. API 키·인터넷 불필요.
// 기본 http://127.0.0.1:11434 의 /api/chat 사용. format=json 으로 verdict JSON 강제.
type OllamaProvider struct {
	Model    string
	Endpoint string
	client   *http.Client
}

func NewOllama(model, endpoint string) *OllamaProvider {
	if endpoint == "" {
		endpoint = "http://127.0.0.1:11434"
	}
	if model == "" {
		model = "llama3.2"
	}
	return &OllamaProvider{
		Model:    model,
		Endpoint: strings.TrimRight(endpoint, "/"),
		client:   &http.Client{Timeout: 60 * time.Second},
	}
}

func (o *OllamaProvider) Name() string { return "ollama" }

func (o *OllamaProvider) Complete(ctx context.Context, system, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model":   o.Model,
		"stream":  false,
		"format":  "json", // 응답을 JSON으로 강제
		"options": map[string]any{"temperature": 0},
		"messages": []any{
			map[string]any{"role": "system", "content": system},
			map[string]any{"role": "user", "content": user},
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", o.Endpoint+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama %d: %s", resp.StatusCode, string(raw))
	}

	var out struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	return out.Message.Content, nil
}
