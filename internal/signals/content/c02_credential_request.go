package content

import (
	"context"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/refdata"
	"github.com/phishlens/phishlens/internal/signals"
)

// C-02: asks for password / SMS code / card data.
func credentialRequest(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Data == nil {
		return nil, nil
	}
	text := fullText(in)
	hits := matchAll(text, func(k *refdata.KeywordSet) []string { return k.Credential }, in.Data.AllKeywords(), 5)
	if len(hits) == 0 {
		return nil, nil
	}
	conf := 0.7
	if len(hits) >= 2 || len(in.Mail.Links) > 0 {
		conf = 0.95
	}
	return []domain.Signal{signals.New(IDCredentialRequest, domain.CategoryContent, 20, conf,
		strings.Join(hits, ", "), in.Lang, strings.Join(hits, ", "))}, nil
}
