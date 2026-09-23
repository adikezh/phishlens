package link

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// L-05: a detonated link renders a password form outside the matched brand's
// official domains. The sandbox itself enforces the SSRF and browser boundary.
func loginForm(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Sandbox == nil {
		return nil, nil
	}
	var out []domain.Signal
	var firstErr error
	for _, link := range in.Mail.Links {
		if link.Href == "" {
			continue
		}
		result, err := in.Sandbox.Detonate(ctx, link.Href)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if result == nil || !result.HasLoginForm {
			continue
		}
		official := false
		if in.Brand != nil && in.Brands != nil {
			official = in.Brands.IsOfficial(in.Brand.Name, link.Domain)
		}
		if official {
			continue
		}
		evidence := link.Href
		if result.FinalURL != "" && result.FinalURL != link.Href {
			evidence += " -> " + result.FinalURL
		}
		out = append(out, signals.New(IDLoginForm, domain.CategoryLink, 30, 0.95, evidence, in.Lang, link.Domain))
		if len(out) >= 3 {
			break
		}
	}
	return out, firstErr
}
