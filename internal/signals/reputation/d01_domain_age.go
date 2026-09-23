package reputation

import (
	"context"
	"fmt"
	"time"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/netutil"
	"github.com/phishlens/phishlens/internal/signals"
)

const youngDomain = 30 * 24 * time.Hour

// D-01: sender domain registered less than 30 days ago (RDAP, cached 7 days).
func domainAge(ctx context.Context, in *signals.Input) ([]domain.Signal, error) {
	if in.Rep == nil || in.Mail.From.Domain == "" {
		return nil, nil
	}
	reg := netutil.RegistrableDomain(in.Mail.From.Domain)
	age, known, err := in.Rep.DomainAge(ctx, reg)
	if err != nil {
		return nil, err
	}
	if !known || age >= youngDomain {
		return nil, nil
	}
	days := int(age.Hours() / 24)
	s := signals.New(IDDomainAge, domain.CategoryReputation, 25, 0.9, fmt.Sprintf("%s registered %d days ago", reg, days), in.Lang, reg, days)
	s.Source = domain.SourceDNS
	return []domain.Signal{s}, nil
}
