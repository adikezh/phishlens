package notify

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
)

// TheHive creates an alert with observables (domains, URLs, hashes) — F-4.6.2.
// TODO: TheHive 5 API /api/v1/alert; also IRIS and Jira adapters with the same shape.
type TheHive struct{}

func (t *TheHive) Name() string { return "thehive" }

// Notify implements Notifier.
func (t *TheHive) Notify(_ context.Context, _ *domain.Submission) error { return ErrNotImplemented }
