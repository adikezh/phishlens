package link

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// L-03: URL shortener hides the destination (expansion TODO).
func shortener(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	var out []domain.Signal
	seen := map[string]bool{}
	for _, l := range in.Mail.Links {
		if !l.IsShortener || seen[l.Domain] {
			continue
		}
		seen[l.Domain] = true
		out = append(out, signals.New(IDShortener, domain.CategoryLink, 10, 0.8, l.Href, in.Lang, l.Domain))
	}
	return out, nil
}
