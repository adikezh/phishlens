// Package imap polls a reporting mailbox (phish@company.kz), extracts forwarded
// messages (.eml attachment or inline forward) and replies with the verdict.
//
// TODO(F-4.1.4): emersion/go-imap/v2 IDLE or poll; message/rfc822 parts → app.Request{Kind: eml};
// inline forwards → parse.Text; reply via SMTP with notify.EmailReply; move to Processed folder.
package imap

import (
	"context"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/ingest"
)

// Receiver is the IMAP runner.
type Receiver struct {
	cfg config.IMAP
}

// New builds the receiver.
func New(cfg config.IMAP) *Receiver { return &Receiver{cfg: cfg} }

func (r *Receiver) Name() string { return "imap" }

// Run implements ingest.Runner.
func (r *Receiver) Run(_ context.Context) error {
	if !r.cfg.Enabled {
		return nil
	}
	return ingest.ErrNotImplemented
}
