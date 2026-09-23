package attachment

import (
	"context"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// A-04: flag active PDF features and embedded files discovered by static scan.
func pdfActive(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Mail.PDF == nil {
		return nil, nil
	}
	p := in.Mail.PDF
	var out []domain.Signal
	if p.HasJavaScript || p.HasOpenAction || p.HasAutoAction || p.HasForms || p.HasEmbedded {
		var features []string
		if p.HasJavaScript {
			features = append(features, "javascript")
		}
		if p.HasOpenAction {
			features = append(features, "open action")
		}
		if p.HasAutoAction {
			features = append(features, "additional action")
		}
		if p.HasForms {
			features = append(features, "form")
		}
		if p.HasEmbedded {
			features = append(features, "embedded file")
		}
		out = append(out, signals.New(IDPDFActive, domain.CategoryAttachment, 25, 0.9, strings.Join(features, ", "), in.Lang, strings.Join(features, ", ")))
	}
	return out, nil
}
