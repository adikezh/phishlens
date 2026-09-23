package header

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/netutil"
	"github.com/phishlens/phishlens/internal/signals"
)

// H-03: Return-Path domain differs from From domain and is not a known ESP of the brand.
// Newsletters legitimately bounce elsewhere, hence the low weight / confidence.
func returnPathMismatch(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	m := in.Mail
	if m.ReturnPath.Domain == "" || m.From.Domain == "" || netutil.SameRegistrable(m.ReturnPath.Domain, m.From.Domain) {
		return nil, nil
	}
	if in.Brand != nil && in.Brands != nil && in.Brands.IsOfficial(in.Brand.Name, m.ReturnPath.Domain) {
		return nil, nil // brand's ESP
	}
	return []domain.Signal{signals.New(IDReturnPathMismatch, domain.CategoryHeader, 10, 0.7,
		"Return-Path: "+m.ReturnPath.Addr, in.Lang, m.ReturnPath.Domain, m.From.Domain)}, nil
}
