package domainsig

import (
	"context"
	"strings"

	"golang.org/x/net/idna"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
	"github.com/phishlens/phishlens/internal/similarity"
)

// D-03: sender domain uses punycode or mixes scripts.
func punycodeMixed(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	d := in.Mail.From.Domain
	if d == "" {
		return nil, nil
	}
	var out []domain.Signal
	if strings.Contains(d, "xn--") {
		uni, err := idna.ToUnicode(d)
		ev := d
		if err == nil {
			ev = d + " (" + uni + ")"
		}
		out = append(out, signals.New(IDPunycode, domain.CategoryDomain, 20, 0.9, ev, in.Lang, d))
		if err == nil && similarity.HasMixedScript(uni) {
			out = append(out, signals.New(IDMixedScript, domain.CategoryDomain, 25, 0.95, uni, in.Lang, uni))
		}
		return out, nil
	}
	if similarity.HasMixedScript(d) {
		out = append(out, signals.New(IDMixedScript, domain.CategoryDomain, 25, 0.95, d, in.Lang, d))
	}
	return out, nil
}
