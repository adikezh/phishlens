package reputation

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// D-02 / R-02: sender or link domain present in a TI feed (URLhaus, OpenPhish, local blocklist).
func domainListed(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Rep == nil {
		return nil, nil
	}
	hosts := append([]string{in.Mail.From.Domain}, in.Mail.LinkDomains()...)
	var out []domain.Signal
	var firstErr error
	for _, h := range hosts {
		if h == "" {
			continue
		}
		listed, source, err := in.Rep.DomainListed(ctx, h)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if listed {
			s := signals.New(IDDomainListed, domain.CategoryReputation, 40, 1, h+" @ "+source, in.Lang, h, source)
			s.Source = domain.SourceTI
			out = append(out, s)
		}
	}
	return out, firstErr
}
