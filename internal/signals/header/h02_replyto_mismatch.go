package header

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/netutil"
	"github.com/phishlens/phishlens/internal/signals"
)

// H-02: Reply-To registrable domain differs from From domain.
func replyToMismatch(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	m := in.Mail
	if m.ReplyTo.Domain == "" || m.From.Domain == "" || netutil.SameRegistrable(m.ReplyTo.Domain, m.From.Domain) {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDReplyToMismatch, domain.CategoryHeader, 15, 0.9,
		"Reply-To: "+m.ReplyTo.Addr+" | From: "+m.From.Addr, in.Lang, m.ReplyTo.Domain, m.From.Domain)}, nil
}
