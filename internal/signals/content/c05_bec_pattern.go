package content

import (
	"context"
	"regexp"
	"strings"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/refdata"
	"github.com/phishlens/phishlens/internal/signals"
)

var reExecTitle = regexp.MustCompile(`(?i)(ceo|cfo|генеральн\w* директор|директор|руководител|founder|president|managing director|бас директор)`)

// C-05: executive impersonation — authority (title in name/signature) + a money/
// purchase request + unavailability/secrecy phrases. Two of three components fire.
func becPattern(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Data == nil {
		return nil, nil
	}
	text := fullText(in)
	sets := in.Data.AllKeywords()
	bec := matchAll(text, func(k *refdata.KeywordSet) []string { return k.BEC }, sets, 6)
	finance := matchAll(text, func(k *refdata.KeywordSet) []string { return k.Finance }, sets, 3)
	authority := reExecTitle.MatchString(in.Mail.From.Display) || reExecTitle.MatchString(lastPart(in.Mail.Text()))

	components := 0
	if len(bec) > 0 {
		components++
	}
	if len(finance) > 0 {
		components++
	}
	if authority {
		components++
	}
	if components < 2 || len(bec) == 0 {
		return nil, nil
	}
	conf := 0.75
	if components == 3 {
		conf = 1
	}
	ev := strings.Join(append(bec, finance...), ", ")
	if authority {
		ev += " | signature: executive"
	}
	return []domain.Signal{signals.New(IDBECPattern, domain.CategoryContent, 40, conf, ev, in.Lang, strings.Join(bec, ", "))}, nil
}

func lastPart(s string) string {
	if len(s) > 400 {
		return s[len(s)-400:]
	}
	return s
}
