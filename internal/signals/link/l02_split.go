package link

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func filterLinkSignal(id string, ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	out, err := ipHost(ctx, in)
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

func ipOnly(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterLinkSignal(IDIPHost, ctx, in)
}

func nonstandardPortOnly(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterLinkSignal(IDNonstandardPort, ctx, in)
}
