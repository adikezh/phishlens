package content

import (
	"context"
	"fmt"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// C-08: message body is (almost) empty while inline images are present.
func imageOnly(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	m := in.Mail
	if len(m.Images) == 0 || m.OCRText != "" {
		return nil, nil
	}
	if len(strings.Fields(m.TextBody)) > 15 {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDImageOnly, domain.CategoryContent, 10, 0.8,
		fmt.Sprintf("%d image(s), %d words", len(m.Images), len(strings.Fields(m.TextBody))), in.Lang)}, nil
}
