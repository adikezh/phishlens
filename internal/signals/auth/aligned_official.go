package auth

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// alignedOfficial (F-4.5.3): SPF + DKIM + DMARC pass and the sender is on the
// brand's official domains → strong negative weight.
func alignedOfficial(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Brand == nil || !in.Brand.Official || !in.Mail.AuthResults.AllPass() {
		return nil, nil
	}
	if in.Data != nil {
		// a free-mail account passing DKIM is not "the brand" (gmail.com ≠ Google)
		if _, free := in.Data.FreeMailDomains[in.Mail.From.Domain]; free {
			return nil, nil
		}
	}
	return []domain.Signal{signals.New(IDAlignedOfficial, domain.CategoryAuth, -40, 1,
		"spf=pass dkim=pass dmarc=pass from "+in.Mail.From.Domain, in.Lang, in.Brand.Name)}, nil
}
