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
var reKZIdentifier = regexp.MustCompile(`\b\d{12}\b`)

// C-06: finance vocabulary combined with a request; bank-detail change is high confidence.
func financeRequest(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Data == nil {
		return nil, nil
	}
	text := fullText(in)
	validID := ""
	for _, candidate := range reKZIdentifier.FindAllString(text, -1) {
		if validKZIdentifier(candidate) {
			validID = candidate
			break
		}
	}
	if m := reBankChange.FindString(text); m != "" {
		evidence := m
		if validID != "" {
			evidence += "; valid KZ IIN/BIN " + validID
		}
		return []domain.Signal{signals.New(IDFinanceRequest, domain.CategoryContent, 10, 1, evidence, in.Lang, evidence)}, nil
	}
	hits := matchAll(text, func(k *refdata.KeywordSet) []string { return k.Finance }, in.Data.AllKeywords(), 4)
	if len(hits) < 2 {
		return nil, nil
	}
	confidence := density(len(hits), text) * 0.8
	evidence := strings.Join(hits, ", ")
	if validID != "" {
		confidence = min(1, confidence+0.15)
		evidence += "; valid KZ IIN/BIN " + validID
	}
	return []domain.Signal{signals.New(IDFinanceRequest, domain.CategoryContent, 10, confidence,
		evidence, in.Lang, evidence)}, nil
}

// validKZIdentifier validates the mod-11 checksum used by 12-digit KZ IIN/BIN.
func validKZIdentifier(value string) bool {
	if len(value) != 12 || strings.Trim(value, "0123456789") != "" || strings.Trim(value, "0") == "" {
		return false
	}
	digits := make([]int, 12)
	for i := range digits {
		digits[i] = int(value[i] - '0')
	}
	check := func(weights []int) int {
		sum := 0
		for i := 0; i < 11; i++ {
			sum += digits[i] * weights[i]
		}
		return sum % 11
	}
	weights := make([]int, 11)
	for i := range weights {
		weights[i] = i + 1
	}
	control := check(weights)
	if control == 10 {
		for i := range weights {
			weights[i] = i + 3
		}
		control = check(weights)
	}
	return control < 10 && control == digits[11]
}
