package content

import (
	"context"
	"regexp"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/refdata"
	"github.com/phishlens/phishlens/internal/signals"
)

// reBankChange spots "bank details changed" phrasing (invoice fraud).
var reBankChange = regexp.MustCompile(`(?i)(нов\w+ реквизит|смен\w+ реквизит|измен\w+ реквизит|new bank details|updated (bank|banking) details|changed our bank|жаңа реквизит)`)

// C-06: finance vocabulary combined with a request; bank-detail change is high confidence.
func financeRequest(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Data == nil {
		return nil, nil
	}
	text := fullText(in)
	if m := reBankChange.FindString(text); m != "" {
		return []domain.Signal{signals.New(IDFinanceRequest, domain.CategoryContent, 10, 1, m, in.Lang, m)}, nil
	}
	hits := matchAll(text, func(k *refdata.KeywordSet) []string { return k.Finance }, in.Data.AllKeywords(), 4)
	if len(hits) < 2 {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDFinanceRequest, domain.CategoryContent, 10, density(len(hits), text)*0.8,
		strings.Join(hits, ", "), in.Lang, strings.Join(hits, ", "))}, nil
}
