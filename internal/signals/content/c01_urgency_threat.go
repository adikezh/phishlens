package content

import (
	"context"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/refdata"
	"github.com/phishlens/phishlens/internal/signals"
)

// C-01: urgency and threat vocabulary, weighted by density.
func urgencyThreat(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Data == nil {
		return nil, nil
	}
	text := fullText(in)
	sets := in.Data.AllKeywords()
	var out []domain.Signal
	if hits := matchAll(text, func(k *refdata.KeywordSet) []string { return k.Urgency }, sets, 5); len(hits) > 0 {
		out = append(out, signals.New(IDUrgency, domain.CategoryContent, 10, density(len(hits), text),
			strings.Join(hits, ", "), in.Lang, strings.Join(hits, ", ")))
	}
	if hits := matchAll(text, func(k *refdata.KeywordSet) []string { return k.Threat }, sets, 5); len(hits) > 0 {
		out = append(out, signals.New(IDThreat, domain.CategoryContent, 10, density(len(hits), text),
			strings.Join(hits, ", "), in.Lang, strings.Join(hits, ", ")))
	}
	return out, nil
}
