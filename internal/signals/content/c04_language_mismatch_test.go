package content

import (
	"context"
	"testing"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

func TestLanguageMismatchRequiresKnownDifferentLocales(t *testing.T) {
	in := &signals.Input{Lang: "en", Brand: &domain.BrandMatch{Name: "Kaspi", Locale: "kz"}, Mail: &domain.ParsedMail{Language: "en"}}
	out, err := languageMismatch(context.Background(), in)
	if err != nil || len(out) != 1 || out[0].ID != IDLanguageMismatch {
		t.Fatalf("mismatch = %#v, err=%v", out, err)
	}

	in.Mail.Language = ""
	out, err = languageMismatch(context.Background(), in)
	if err != nil || len(out) != 0 {
		t.Fatalf("unknown language = %#v, err=%v", out, err)
	}
}
