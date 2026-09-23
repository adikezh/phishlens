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

// Ollama talks to a local Ollama server (/api/chat, format=json) — the offline mode.
type Ollama struct {
	name        string
	baseURL     string
	model       string
	visionModel string
	client      *http.Client
}

// NewOllama builds the provider.
func NewOllama(name, baseURL, model, visionModel string, timeout time.Duration) *Ollama {
	return &Ollama{
		name:        name,
		baseURL:     strings.TrimRight(baseURL, "/"),
		model:       model,
		visionModel: visionModel,
		client:      &http.Client{Timeout: timeout},
	}
}

func (o *Ollama) Name() string  { return o.name }
func (o *Ollama) Model() string { return o.model }

// Complete implements Provider.
func (o *Ollama) Complete(ctx context.Context, req Request) (*Response, error) {
	body := map[string]any{
		"model":  o.model,
		"stream": false,
		"format": "json",
		"options": map[string]any{
			"temperature": 0,
			"num_predict": req.MaxTokens,
		},
		"messages": []oaMessage{
			{Role: "system", Content: req.System},
			{Role: "user", Content: req.User},
		},
	}
	b, _ := json.Marshal(body)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/api/chat", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
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
		Model           string    `json:"model"`
		Message         oaMessage `json:"message"`
		PromptEvalCount int       `json:"prompt_eval_count"`
		EvalCount       int       `json:"eval_count"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("llm/%s: decode: %w", o.name, err)
	}
	return &Response{Text: out.Message.Content, Model: out.Model, InputTokens: out.PromptEvalCount, OutputTokens: out.EvalCount}, nil
}

// TODO(F-4.1.9): Vision(ctx, image, prompt) using visionModel and "images": [base64].
