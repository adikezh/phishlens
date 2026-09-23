package link

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
	"github.com/phishlens/phishlens/internal/similarity"
)

// punycode / mixed-script link hosts (D-03 applied to links).
func punycode(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	var out []domain.Signal
	seen := map[string]bool{}
	for _, l := range in.Mail.Links {
		if l.Domain == "" || seen[l.Domain] {
			continue
		}
		if l.Punycode || similarity.HasMixedScript(l.Domain) {
			seen[l.Domain] = true
			out = append(out, signals.New(IDPunycode, domain.CategoryLink, 20, 0.9, l.Href, in.Lang, l.Domain))
		}
	}
	return out, nil
}
