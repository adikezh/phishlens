package auth

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// unverified: message has transport headers but no Authentication-Results at all.
func unverified(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	m := in.Mail
	if len(m.Received) == 0 || m.AuthResults.Source != "" {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDUnverified, domain.CategoryAuth, 3, 0.5, "no Authentication-Results header", in.Lang)}, nil
}
