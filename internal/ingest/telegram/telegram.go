// Package telegram is the bot receiver: forward text or a screenshot → verdict.
// TODO(F-4.1.8): go-telegram/bot long polling; /start <org-code> binds chat to org;
// photos → app.Request{Kind: image}; text → Kind: text; reply with verdict + top signals.
package telegram

import (
	"context"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/ingest"
)

// Receiver is the Telegram runner.
type Receiver struct{ cfg config.Telegram }

// New builds the receiver.
func New(cfg config.Telegram) *Receiver { return &Receiver{cfg: cfg} }

func (r *Receiver) Name() string { return "telegram" }

// Run implements ingest.Runner.
func (r *Receiver) Run(_ context.Context) error {
	if !r.cfg.Enabled {
		return nil
	}
	return ingest.ErrNotImplemented
}
