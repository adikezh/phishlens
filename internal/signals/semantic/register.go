// Package semantic turns the validated LLM opinion into a signal of category
// "semantic" with weight up to ±25 (F-4.4.3). It never decides the verdict on its own.
package semantic

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

const (
	IDLLMPhishing   = "semantic.llm_phishing"
	IDLLMSuspicious = "semantic.llm_suspicious"
	IDLLMClean      = "semantic.llm_clean"
)

// Register adds the semantic check.
func Register(r *signals.Registry) {
	r.Register(signals.NewFunc(IDLLMPhishing, domain.CategorySemantic, llmOpinion))
}

func llmOpinion(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	o := in.LLM
	if o == nil {
		return nil, nil
	}
	var id string
	var weight int
	switch o.VerdictOpinion {
	case "phishing":
		id, weight = IDLLMPhishing, 25
	case "suspicious":
		id, weight = IDLLMSuspicious, 10
	case "clean":
		id, weight = IDLLMClean, -15
	default:
		return nil, nil
	}
	conf := 0.8
	if len(o.Highlights) >= 2 {
		conf = 1
	}
	s := signals.New(id, domain.CategorySemantic, weight, conf, signals.Truncate(o.Summary, 200), in.Lang)
	s.Source = domain.SourceLLM
	return []domain.Signal{s}, nil
}
