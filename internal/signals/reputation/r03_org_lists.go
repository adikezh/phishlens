package reputation

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// R-03: organisation allow/block lists override the score (hard rules in score.Engine).
func orgLists(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Lists == nil {
		return nil, nil
	}
	candidates := []string{in.Mail.From.Addr, in.Mail.From.Domain, in.Mail.ReplyTo.Addr, in.Mail.ReplyTo.Domain}
	candidates = append(candidates, in.Mail.LinkDomains()...)
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if ok, matched := in.Lists.IsBlocked(ctx, c); ok {
			return []domain.Signal{signals.New(IDOrgBlocklist, domain.CategoryReputation, 100, 1, matched, in.Lang, matched)}, nil
		}
	}
	for _, c := range []string{in.Mail.From.Addr, in.Mail.From.Domain} {
		if c == "" {
			continue
		}
		if ok, matched := in.Lists.IsAllowed(ctx, c); ok {
			return []domain.Signal{signals.New(IDOrgAllowlist, domain.CategoryReputation, -30, 1, matched, in.Lang, matched)}, nil
		}
	}
	return nil, nil
}
