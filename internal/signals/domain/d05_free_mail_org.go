package domainsig

import (
	"context"
	"regexp"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// reOrgSignature spots titles / org words in the display name or signature block.
// NB: Go's \b is ASCII-only, so Unicode-aware boundaries are spelled out.
var reOrgSignature = regexp.MustCompile(`(?i)(?:^|[^\p{L}])(ceo|cfo|cto|director|директор|руководител|бухгалтер|manager|менеджер|отдел|department|басшы|bank|банк|служба|support|поддержк)`)

// D-05: message signed on behalf of an organisation / executive but sent from a free
// mail provider, or a brand is imitated from free mail.
func freeMailOrg(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	m := in.Mail
	if m.From.Domain == "" || in.Data == nil {
		return nil, nil
	}
	if _, free := in.Data.FreeMailDomains[m.From.Domain]; !free {
		return nil, nil
	}
	conf := 0.0
	switch {
	case reOrgSignature.MatchString(m.From.Display):
		conf = 1 // title right in the display name: "Аскар Нурланов (Генеральный директор)"
	case in.Brand != nil && !in.Brand.Official:
		conf = 0.9
	case reOrgSignature.MatchString(lastLines(m.Text(), 6)):
		conf = 0.8
	}
	if conf == 0 {
		return nil, nil
	}
	return []domain.Signal{signals.New(IDFreeMailOrg, domain.CategoryDomain, 15, conf,
		"From: "+m.From.String(), in.Lang, m.From.Domain)}, nil
}

func lastLines(s string, n int) string {
	lines := splitLines(s)
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if l := s[start:i]; len(l) > 0 {
				out = append(out, l)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
