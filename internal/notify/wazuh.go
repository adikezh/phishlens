package notify

import (
	"context"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

// Wazuh sends a custom event when verdict ≥ min_verdict (F-4.9.1).
//
// TODO: two transports — (a) syslog/agent socket JSON line with "phishlens" decoder,
// (b) Wazuh API POST /events (4.x) with basic auth. Fields = notify.Event.
type Wazuh struct {
	cfg      config.Wazuh
	password string
}

// NewWazuh builds the notifier.
func NewWazuh(cfg config.Wazuh, password string) *Wazuh {
	return &Wazuh{cfg: cfg, password: password}
}

func (w *Wazuh) Name() string { return "wazuh" }

// Notify implements Notifier.
func (w *Wazuh) Notify(_ context.Context, sub *domain.Submission) error {
	if sub.Result == nil {
		return nil
	}
	if sub.Result.Verdict.Rank() < domain.Verdict(w.cfg.MinVerdict).Rank() {
		return nil
	}
	return ErrNotImplemented
}
