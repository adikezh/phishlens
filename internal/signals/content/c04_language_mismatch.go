package content

import (
	"context"
	"fmt"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// languageMismatch is deliberately narrow: it needs both a detected message
// language and a configured brand locale. Missing/unknown language is not a
// mismatch, and the heuristic does not claim to detect machine translation.
func languageMismatch(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in == nil || in.Mail == nil || in.Brand == nil {
		return nil, nil
	}
	messageLang := normalizeLocale(in.Mail.Language)
	brandLang := normalizeLocale(in.Brand.Locale)
	if messageLang == "" || brandLang == "" || messageLang == brandLang {
		return nil, nil
	}
	evidence := fmt.Sprintf("message=%s, brand=%s (%s)", messageLang, brandLang, in.Brand.Name)
	return []domain.Signal{signals.New(IDLanguageMismatch, domain.CategoryContent, 12, 0.8, evidence, in.Lang, messageLang, brandLang, in.Brand.Name)}, nil
}

func normalizeLocale(locale string) string {
	locale = strings.ToLower(strings.TrimSpace(locale))
	if i := strings.IndexAny(locale, "-_"); i >= 0 {
		locale = locale[:i]
	}
	return locale
}
