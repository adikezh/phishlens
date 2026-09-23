package link

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// brandLookalike (D-04 for links): a link host imitates a brand without belonging to it.
func brandLookalike(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Brands == nil {
		return nil, nil
	}
	var out []domain.Signal
	for _, host := range in.Mail.LinkDomains() {
		name, official, method, score := in.Brands.MatchDomain(host)
		if name == "" || official {
			continue
		}
		out = append(out, signals.New(IDBrandLookalike, domain.CategoryLink, 30, score,
			host+" ~ "+name+" ("+method+")", in.Lang, host, name))
		if len(out) >= 3 {
			break
		}
	}
	return out, nil
}
