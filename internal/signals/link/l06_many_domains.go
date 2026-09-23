package link

import (
	"context"
	"fmt"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/netutil"
	"github.com/phishlens/phishlens/internal/signals"
)

// L-06: links point to many unrelated registrable domains. Cloud-form links
// with credential keywords are registered separately in l04_l06_specialized.go.
func manyDomains(_ context.Context, in *signals.Input) ([]domain.Signal, error) {
	regs := map[string]bool{}
	for _, h := range in.Mail.LinkDomains() {
		regs[netutil.RegistrableDomain(h)] = true
	}
	if len(regs) < 5 {
		return nil, nil
	}
	conf := min(1, float64(len(regs))/10)
	return []domain.Signal{signals.New(IDManyDomains, domain.CategoryLink, 8, conf,
		fmt.Sprintf("%d registrable domains", len(regs)), in.Lang, len(regs))}, nil
}
