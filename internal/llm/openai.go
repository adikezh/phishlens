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

// OpenAICompatible talks to /chat/completions (OpenRouter, vLLM, LM Studio, OpenAI…).
type OpenAICompatible struct {
	name    string
	baseURL string
	model   string
	apiKey  string
	client  *http.Client
}

// NewOpenAICompatible builds the provider.
func NewOpenAICompatible(name, baseURL, model, apiKey string, timeout time.Duration) *OpenAICompatible {
	return &OpenAICompatible{
		name:    name,
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		apiKey:  apiKey,
		client:  &http.Client{Timeout: timeout},
	}
}

func (o *OpenAICompatible) Name() string  { return o.name }
func (o *OpenAICompatible) Model() string { return o.model }

type oaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Complete implements Provider.
func (o *OpenAICompatible) Complete(ctx context.Context, req Request) (*Response, error) {
	body := map[string]any{
		"model":           o.model,
		"temperature":     0,
		"max_tokens":      req.MaxTokens,
		"response_format": map[string]string{"type": "json_object"},
		"messages": []oaMessage{
			{Role: "system", Content: req.System},
			{Role: "user", Content: req.User},
		},
	}
	b, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
	}
	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm/%s: %w", o.name, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("llm/%s: status %d: %s", o.name, resp.StatusCode, truncateRunes(string(raw), 300))
	}
	var out struct {
		Model   string `json:"model"`
		Choices []struct {
			Message oaMessage `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("llm/%s: decode: %w", o.name, err)
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("llm/%s: empty choices", o.name)
	}
	model := out.Model
	if model == "" {
		model = o.model
	}
	return &Response{
		Text:         out.Choices[0].Message.Content,
		Model:        model,
		InputTokens:  out.Usage.PromptTokens,
		OutputTokens: out.Usage.CompletionTokens,
	}, nil
}
