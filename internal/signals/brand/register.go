// Package brand implements F-4.3.2/F-4.3.3: brand matching from domains,
// keywords, logo pHash, and extracted image colour palettes, followed by the
// strong signal for an unofficial sender.
package brand

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// IDSenderMismatch is the strong (+35) brand impersonation signal.
const IDSenderMismatch = "brand.sender_mismatch"

// Register adds brand checks.
func Register(r *signals.Registry) {
	r.Register(signals.NewFunc(IDSenderMismatch, domain.CategoryBrand, senderMismatch))
}

func senderMismatch(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	b := in.Brand
	if b == nil || b.Official || in.Mail.From.Domain == "" {
		return nil, nil
	}
	if in.Data != nil {
		// a private person writing about Kaspi from gmail is not impersonation by itself;
		// require either a lookalike domain or strong keyword evidence.
		if _, free := in.Data.FreeMailDomains[in.Mail.From.Domain]; free && b.Method == "keyword" && b.Score < 1 {
			return nil, nil
		}
	}
	return []domain.Signal{signals.New(IDSenderMismatch, domain.CategoryBrand, 35, b.Score,
		b.Name+" via "+b.Method+", From: "+in.Mail.From.Domain, in.Lang, b.Name, in.Mail.From.Domain)}, nil
}
