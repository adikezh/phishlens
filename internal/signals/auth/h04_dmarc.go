package auth

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func dmarc(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	ar := in.Mail.AuthResults
	if ar.DMARC == domain.AuthFail || ar.DMARC == domain.AuthPermError {
		return []domain.Signal{signals.New(IDDMARCFail, domain.CategoryAuth, 25, 0.95, "dmarc="+string(ar.DMARC), in.Lang, in.Mail.From.Domain)}, nil
	}
	return nil, nil
}
