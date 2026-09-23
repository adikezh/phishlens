package link

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// L-01: anchor text is a URL/domain that differs from the real href host.
func textHrefMismatch(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	var out []domain.Signal
	for _, l := range in.Mail.Links {
		if !l.Mismatch {
			continue
		}
		out = append(out, signals.New(IDTextHrefMismatch, domain.CategoryLink, 20, 0.95,
			l.Text+" -> "+l.Href, in.Lang, l.Text, l.Domain))
		if len(out) >= 3 {
			break
		}
	}
	return out, nil
}
