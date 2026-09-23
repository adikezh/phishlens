package domainsig

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// D-04: sender domain resembles a brand (typosquat, homoglyph, DL ≤ 2, brand token
// on a foreign domain) and is not an official domain.
func brandLookalike(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Brands == nil || in.Mail.From.Domain == "" {
		return nil, nil
	}
	name, official, method, score := in.Brands.MatchDomain(in.Mail.From.Domain)
	if name == "" || official {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDBrandLookalike, domain.CategoryDomain, 30, score,
		in.Mail.From.Domain+" ~ "+name+" ("+method+")", in.Lang, in.Mail.From.Domain, name)}, nil
}
