package header

import (
	"context"
	"time"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/parse"
	"github.com/phishlens/phishlens/internal/signals"
)

const maxSkew = 24 * time.Hour

// H-08: Date header is in the future or differs from the first Received hop by > 24h.
func dateSkew(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	m := in.Mail
	if m.Date.IsZero() {
		return nil, nil
	}
	ref := parse.FirstReceivedTime(m.Received)
	if ref.IsZero() {
		ref = time.Now()
		if m.Date.Before(ref.Add(maxSkew)) {
			return nil, nil // only "far future" is suspicious without Received
		}
	}
	diff := m.Date.Sub(ref)
	if diff < 0 {
		diff = -diff
	}
	if diff <= maxSkew {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDDateSkew, domain.CategoryHeader, 8, 0.7,
		"Date: "+m.Date.Format(time.RFC1123Z), in.Lang, m.Date.Format("2006-01-02 15:04"), ref.Format("2006-01-02 15:04"))}, nil
}
