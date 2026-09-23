package domainsig

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/netutil"
	"github.com/phishlens/phishlens/internal/signals"
)

// D-06: sender or link TLD from the risky list; confidence scales with the list's risk value.
func riskyTLD(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Data == nil {
		return nil, nil
	}
	hosts := []string{in.Mail.From.Domain}
	hosts = append(hosts, in.Mail.LinkDomains()...)
	seen := map[string]bool{}
	var out []domain.Signal
	for _, h := range hosts {
		tld := netutil.TLD(h)
		if tld == "" || seen[tld] {
			continue
		}
		risk, ok := in.Data.RiskyTLDs[tld]
		if !ok || risk <= 0 {
			continue
		}
		seen[tld] = true
		out = append(out, signals.New(IDRiskyTLD, domain.CategoryDomain, 10, float64(risk)/10, h, in.Lang, tld))
	}
	return out, nil
}
