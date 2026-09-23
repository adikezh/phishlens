// Package score turns signals into a score, verdict and recommendations
// (ТЗ §4.5): Score = clamp(Σ weight × confidence, 0, 100), thresholds, hard
// rules and conflict detection (needs_review). Every contribution stays visible
// in Analysis.Signals for explainability (F-4.5.4).
package score

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Thresholds are verdict cut-offs.
type Thresholds struct {
	Phishing   int `yaml:"phishing"`
	Suspicious int `yaml:"suspicious"`
}

// Weights is data/weights.yaml; organisations may override entries (F-4.5.1).
type Weights struct {
	Thresholds Thresholds     `yaml:"thresholds"`
	Signals    map[string]int `yaml:"signals"`
}

// DefaultThresholds per ТЗ F-4.5.2.
var DefaultThresholds = Thresholds{Phishing: 70, Suspicious: 40}

// LoadWeights decodes weights.yaml.
func LoadWeights(r io.Reader) (*Weights, error) {
	var w Weights
	if err := yaml.NewDecoder(r).Decode(&w); err != nil {
		return nil, fmt.Errorf("weights: decode: %w", err)
	}
	if w.Signals == nil {
		w.Signals = map[string]int{}
	}
	if w.Thresholds.Phishing == 0 {
		w.Thresholds = DefaultThresholds
	}
	return &w, nil
}

// Merge returns a copy with overrides applied (org-level customisation).
func (w *Weights) Merge(overrides map[string]int, th *Thresholds) *Weights {
	out := &Weights{Thresholds: w.Thresholds, Signals: make(map[string]int, len(w.Signals))}
	for k, v := range w.Signals {
		out.Signals[k] = v
	}
	for k, v := range overrides {
		out.Signals[k] = v
	}
	if th != nil {
		out.Thresholds = *th
	}
	return out
}
