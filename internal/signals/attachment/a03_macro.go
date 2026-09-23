package attachment

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// A-03: Office document with a VBA project.
func macro(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	var out []domain.Signal
	for _, a := range in.Mail.Attachments {
		if a.MacroDetected {
			out = append(out, signals.New(IDMacro, domain.CategoryAttachment, 30, 0.95, a.Name, in.Lang, a.Name))
		}
	}
	return out, nil
}
