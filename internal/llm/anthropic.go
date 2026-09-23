package llm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// Anthropic uses the official SDK (Messages API). The system prompt carries the
// injection-isolation rules; the email is wrapped in <email> tags in the user turn.
type Anthropic struct {
	name   string
	model  string
	client anthropic.Client
}

// NewAnthropic builds the provider; baseURL may be empty (api.anthropic.com).
func NewAnthropic(name, baseURL, model, apiKey string, timeout time.Duration) *Anthropic {
	opts := []option.RequestOption{option.WithRequestTimeout(timeout)}
	if apiKey != "" {
		opts = append(opts, option.WithAPIKey(apiKey))
	}
	if baseURL != "" {
		opts = append(opts, option.WithBaseURL(baseURL))
	}
	if model == "" {
		model = "claude-opus-5"
	}
	return &Anthropic{name: name, model: model, client: anthropic.NewClient(opts...)}
}

func (a *Anthropic) Name() string  { return a.name }
func (a *Anthropic) Model() string { return a.model }

// Complete implements Provider.
func (a *Anthropic) Complete(ctx context.Context, req Request) (*Response, error) {
	maxTokens := int64(req.MaxTokens)
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(a.model),
		MaxTokens: maxTokens,
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(req.User)),
		},
	}
	if req.System != "" {
		params.System = []anthropic.TextBlockParam{{Text: req.System}}
	}
	msg, err := a.client.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("llm/%s: %w", a.name, err)
	}
	if msg.StopReason == anthropic.StopReasonRefusal {
		return nil, fmt.Errorf("llm/%s: model refused the request", a.name)
	}
	var sb strings.Builder
	for _, block := range msg.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			sb.WriteString(t.Text)
		}
	}
	return &Response{
		Text:         sb.String(),
		Model:        string(msg.Model),
		InputTokens:  int(msg.Usage.InputTokens),
		OutputTokens: int(msg.Usage.OutputTokens),
	}, nil
}
