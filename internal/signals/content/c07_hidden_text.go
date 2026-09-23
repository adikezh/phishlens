package content

import (
	"context"
	"regexp"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

var hiddenPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"font-size:0", regexp.MustCompile(`(?i)font-size\s*:\s*0(px|pt|em|%)?\b`)},
	{"display:none", regexp.MustCompile(`(?i)display\s*:\s*none`)},
	{"visibility:hidden", regexp.MustCompile(`(?i)visibility\s*:\s*hidden`)},
	{"white text", regexp.MustCompile(`(?i)color\s*:\s*(#fff(fff)?|white)\b`)},
	{"opacity:0", regexp.MustCompile(`(?i)opacity\s*:\s*0(\.0+)?\b`)},
}

// C-07: hidden text techniques inside the HTML body.
func hiddenText(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	h := in.Mail.HTMLBody
	if h == "" {
		return nil, nil
	}
	for _, p := range hiddenPatterns {
		if m := p.re.FindString(h); m != "" {
			return []domain.Signal{signals.New(IDHiddenText, domain.CategoryContent, 15, 0.8, m, in.Lang, p.name)}, nil
		}
	}
	return nil, nil
}
