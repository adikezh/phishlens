package auth

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func spf(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	ar := in.Mail.AuthResults
	switch ar.SPF {
	case domain.AuthFail, domain.AuthPermError:
		return []domain.Signal{signals.New(IDSPFFail, domain.CategoryAuth, 20, 0.9, "spf="+string(ar.SPF), in.Lang, in.Mail.From.Domain)}, nil
	case domain.AuthSoftFail:
		return []domain.Signal{signals.New(IDSPFSoftFail, domain.CategoryAuth, 10, 0.8, "spf=softfail", in.Lang, in.Mail.From.Domain)}, nil
	}
	return nil, nil
}
