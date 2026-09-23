// Package content implements body heuristics C-01 … C-08 (ТЗ §4.2) over the
// ru/en/kz dictionaries in data/keywords.
// TODO(C-04): language mismatch vs brand locale / machine translation (heuristics + LLM).
// TODO(C-06): IIN/BIN checksum validation.
package content

import (
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/refdata"
	"github.com/phishlens/phishlens/internal/signals"
)

const (
	IDUrgency           = "content.urgency"            // C-01
	IDThreat            = "content.threat"             // C-01
	IDCredentialRequest = "content.credential_request" // C-02
	IDGenericGreeting   = "content.generic_greeting"   // C-03
	IDBECPattern        = "content.bec_pattern"        // C-05
	IDFinanceRequest    = "content.finance_request"    // C-06
	IDHiddenText        = "content.hidden_text"        // C-07
	IDImageOnly         = "content.image_only"         // C-08
)

// Register adds content checks.
func Register(r *signals.Registry) {
	r.Register(
		signals.NewFunc(IDUrgency, domain.CategoryContent, urgencyThreat),
		signals.NewFunc(IDCredentialRequest, domain.CategoryContent, credentialRequest),
		signals.NewFunc(IDGenericGreeting, domain.CategoryContent, genericGreeting),
		signals.NewFunc(IDBECPattern, domain.CategoryContent, becPattern),
		signals.NewFunc(IDFinanceRequest, domain.CategoryContent, financeRequest),
		signals.NewFunc(IDHiddenText, domain.CategoryContent, hiddenText),
		signals.NewFunc(IDImageOnly, domain.CategoryContent, imageOnly),
	)
}

// fullText is subject + body lowercased and ё→е normalised for content matching.
func fullText(in *signals.Input) string {
	return norm(in.Mail.Subject + "\n" + in.Mail.Text())
}

var yo = strings.NewReplacer("ё", "е")

func norm(s string) string { return yo.Replace(strings.ToLower(s)) }

// matchAll returns dictionary entries found in text across every language,
// de-duplicated (after ё/е normalisation), capped at limit.
func matchAll(text string, pick func(*refdata.KeywordSet) []string, sets []*refdata.KeywordSet, limit int) []string {
	seen := map[string]bool{}
	var out []string
	for _, ks := range sets {
		for _, w := range pick(ks) {
			w = norm(w)
			if w == "" || seen[w] || !strings.Contains(text, w) {
				continue
			}
			seen[w] = true
			out = append(out, w)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// density scales confidence: hits per ~100 words, capped at 1.
func density(hits int, text string) float64 {
	words := len(strings.Fields(text))
	if words < 20 {
		words = 20
	}
	return min(1, 0.5+float64(hits)*100/float64(words)*0.25)
}
