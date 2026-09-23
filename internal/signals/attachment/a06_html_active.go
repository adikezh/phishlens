package attachment

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// A-06: HTML attachment containing script/form/iframe (HTML smuggling).
func htmlActive(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	var out []domain.Signal
	for _, a := range in.Mail.Attachments {
		if a.HasActiveContent {
			out = append(out, signals.New(IDHTMLActive, domain.CategoryAttachment, 25, 0.9, a.Name, in.Lang, a.Name))
		}
	}
	return out, nil
}
