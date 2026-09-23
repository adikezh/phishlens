package domainsig

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func filterDomainSignal(id string, ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	out, err := punycodeMixed(ctx, in)
	if err != nil {
		return nil, err
	}
	for _, s := range out {
		if s.ID == id {
			return []domain.Signal{s}, nil
		}
	}
	return nil, nil
}

func punycodeOnly(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterDomainSignal(IDPunycode, ctx, in)
}

func mixedScriptOnly(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterDomainSignal(IDMixedScript, ctx, in)
}
