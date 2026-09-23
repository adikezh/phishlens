package content

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func filterContentSignal(id string, ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	out, err := urgencyThreat(ctx, in)
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

func urgencyOnly(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterContentSignal(IDUrgency, ctx, in)
}
func threatOnly(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	return filterContentSignal(IDThreat, ctx, in)
}
