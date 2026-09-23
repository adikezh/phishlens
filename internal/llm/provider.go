// Package llm is the explanation layer (ТЗ §4.4): providers (OpenAI-compatible,
// Anthropic, Ollama) behind one interface, PII redaction before any external call,
// prompt templates, strict output validation and a hash-keyed cache. The LLM's
// opinion becomes a "semantic" signal — never the verdict.
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrDisabled is returned by Service.Explain when LLM is off.
var ErrDisabled = errors.New("llm: disabled")

// ErrBudget is returned when the hourly/daily budget is exhausted.
var ErrBudget = errors.New("llm: budget exhausted")

// Request is a provider call: already redacted, ready-to-send prompts.
type Request struct {
	System    string
	User      string
	MaxTokens int
}

// Response is the raw provider output plus usage.
type Response struct {
	Text         string
	Model        string
	InputTokens  int
	OutputTokens int
}

// Provider is one backend.
type Provider interface {
	Name() string
	Model() string
	Complete(ctx context.Context, req Request) (*Response, error)
}

// Output is the JSON schema the model must follow (F-4.4.2).
type Output struct {
	VerdictOpinion string   `json:"verdict_opinion"`
	AttackType     string   `json:"attack_type"`
	Summary        string   `json:"summary"`
	Highlights     []Span   `json:"highlights"`
	Tactics        []string `json:"social_engineering_tactics"`
	Recommended    string   `json:"recommended_action"`
	Questions      []string `json:"questions_for_analyst"`
}

// Span mirrors domain.Span.
type Span struct {
	Quote  string `json:"quote"`
	Reason string `json:"reason"`
}

var (
	validVerdicts = map[string]bool{"phishing": true, "suspicious": true, "clean": true}
	validAttacks  = map[string]bool{"credential_harvesting": true, "malware": true, "bec": true, "invoice_fraud": true, "extortion": true, "spam": true, "none": true}
	validTactics  = map[string]bool{"urgency": true, "authority": true, "fear": true, "scarcity": true, "curiosity": true, "reciprocity": true, "trust": true}
	reJSONBlock   = regexp.MustCompile(`(?s)\{.*\}`)
)

// ParseOutput extracts and validates the JSON object from model text; tolerant to
// code fences and prose around it (F-4.4.4: schema validation, no free-form trust).
func ParseOutput(text string) (*Output, error) {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	m := reJSONBlock.FindString(text)
	if m == "" {
		return nil, errors.New("llm: no JSON object in response")
	}
	var out Output
	if err := json.Unmarshal([]byte(m), &out); err != nil {
		return nil, fmt.Errorf("llm: invalid JSON: %w", err)
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return &out, nil
}

// Validate enforces enums and sizes; unknown tactics are dropped, not rejected.
func (o *Output) Validate() error {
	o.VerdictOpinion = strings.ToLower(strings.TrimSpace(o.VerdictOpinion))
	if !validVerdicts[o.VerdictOpinion] {
		return fmt.Errorf("llm: invalid verdict_opinion %q", o.VerdictOpinion)
	}
	o.AttackType = strings.ToLower(strings.TrimSpace(o.AttackType))
	if o.AttackType == "" {
		o.AttackType = "none"
	}
	if !validAttacks[o.AttackType] {
		return fmt.Errorf("llm: invalid attack_type %q", o.AttackType)
	}
	o.Summary = strings.TrimSpace(o.Summary)
	if o.Summary == "" {
		return errors.New("llm: empty summary")
	}
	o.Summary = truncateRunes(o.Summary, 1200)
	o.Recommended = truncateRunes(strings.TrimSpace(o.Recommended), 400)
	if len(o.Highlights) > 8 {
		o.Highlights = o.Highlights[:8]
	}
	for i := range o.Highlights {
		o.Highlights[i].Quote = truncateRunes(strings.TrimSpace(o.Highlights[i].Quote), 200)
		o.Highlights[i].Reason = truncateRunes(strings.TrimSpace(o.Highlights[i].Reason), 300)
	}
	kept := o.Tactics[:0]
	for _, t := range o.Tactics {
		t = strings.ToLower(strings.TrimSpace(t))
		if validTactics[t] {
			kept = append(kept, t)
		}
	}
	o.Tactics = kept
	if len(o.Questions) > 6 {
		o.Questions = o.Questions[:6]
	}
	return nil
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
