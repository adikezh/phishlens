package reputation

import (
	"context"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// R-01: originating IP (earliest Received hop) listed in a DNSBL / AbuseIPDB.
func ipListed(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Rep == nil || len(in.Mail.Received) == 0 {
		return nil, nil
	}
	ip := ""
	for i := len(in.Mail.Received) - 1; i >= 0; i-- {
		if in.Mail.Received[i].IP != "" {
			ip = in.Mail.Received[i].IP
			break
		}
	}
	if ip == "" {
		return nil, nil
	}
	listed, source, err := in.Rep.IPListed(ctx, ip)
	if err != nil {
		return nil, err
	}
	if !listed {
		return nil, nil
	}
	s := signals.New(IDIPListed, domain.CategoryReputation, 30, 0.9, ip+" @ "+source, in.Lang, ip, source)
	s.Source = domain.SourceDNS
	return []domain.Signal{s}, nil
}
