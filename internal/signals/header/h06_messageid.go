package header

import (
	"context"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/netutil"
	"github.com/phishlens/phishlens/internal/signals"
)

// H-06: Message-ID missing, or its domain differs from the From domain.
// Only evaluated when headers are present at all (pasted body-only text has none).
func messageID(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	m := in.Mail
	if len(m.Headers) == 0 || m.From.Domain == "" {
		return nil, nil
	}
	mid := strings.Trim(strings.TrimSpace(m.Header("Message-ID")), "<>")
	if mid == "" {
		return []domain.Signal{signals.New(IDMessageIDMissing, domain.CategoryHeader, 5, 0.6, "no Message-ID header", in.Lang)}, nil
	}
	at := strings.LastIndex(mid, "@")
	if at < 0 {
		return nil, nil
	}
	midDomain := strings.ToLower(mid[at+1:])
	if netutil.SameRegistrable(midDomain, m.From.Domain) {
		return nil, nil
	}
	if in.Brand != nil && in.Brands != nil && in.Brands.IsOfficial(in.Brand.Name, midDomain) {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDMessageIDMismatch, domain.CategoryHeader, 8, 0.6,
		"Message-ID: <"+mid+">", in.Lang, midDomain, m.From.Domain)}, nil
}
