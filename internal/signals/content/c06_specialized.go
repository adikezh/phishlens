package content

import (
	"context"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func bankDetailChange(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	text := fullText(in)
	m := reBankChange.FindString(text)
	if m == "" {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDBankDetailChange, domain.CategoryContent, 15, 0.95,
		m, in.Lang, m)}, nil
}

func kzIdentifier(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	for _, candidate := range reKZIdentifier.FindAllString(fullText(in), -1) {
		if validKZIdentifier(candidate) {
			return []domain.Signal{signals.New(IDKZIdentifier, domain.CategoryContent, 6, 0.7,
				candidate, in.Lang, strings.TrimSpace(candidate))}, nil
		}
	}
	return nil, nil
}
