// Package graph is the Microsoft 365 receiver (same flow as IMAP without IMAP).
// TODO(F-4.1.5): msgraph-sdk-go, client-credentials flow, /users/{mailbox}/messages delta query.
package graph

import (
	"context"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/ingest"
)

// Receiver is the Graph runner.
type Receiver struct{ cfg config.Graph }

// New builds the receiver.
func New(cfg config.Graph) *Receiver { return &Receiver{cfg: cfg} }

func (r *Receiver) Name() string { return "graph" }

// Run implements ingest.Runner.
func (r *Receiver) Run(_ context.Context) error {
	if !r.cfg.Enabled {
		return nil
	}
	return ingest.ErrNotImplemented
}
