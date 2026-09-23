package auth

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func dkim(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	ar := in.Mail.AuthResults
	switch ar.DKIM {
	case domain.AuthFail, domain.AuthPermError:
		return []domain.Signal{signals.New(IDDKIMFail, domain.CategoryAuth, 15, 0.85, "dkim="+string(ar.DKIM), in.Lang)}, nil
	case domain.AuthNone:
		// only meaningful when the sender claims to be an organisation (brand detected)
		if in.Brand != nil {
			return []domain.Signal{signals.New(IDDKIMNone, domain.CategoryAuth, 5, 0.6, "dkim=none", in.Lang)}, nil
		}
	}
	return nil, nil
}
