package header

import (
	"context"
	"regexp"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

var reEmailInName = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// H-01: display name contains an email address different from the real From address
// ("ceo@company.kz" <attacker@gmail.com>).
func displayNameEmail(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	from := in.Mail.From
	shown := reEmailInName.FindString(from.Display)
	if shown == "" || strings.EqualFold(shown, from.Addr) {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDDisplayNameEmail, domain.CategoryHeader, 20, 0.95,
		"From: "+from.String(), in.Lang, shown, from.Addr)}, nil
}
