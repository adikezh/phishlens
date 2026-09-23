// Package reputation implements network-backed checks R-01 … R-03 and D-01/D-02 via
// signals.ReputationLookup / ListLookup. Each check tolerates lookup errors:
// the stage degrades with a warning instead of failing the verdict (ТЗ §5).
package reputation

import (
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

const (
	IDOrgBlocklist = "reputation.org_blocklist" // R-03
	IDOrgAllowlist = "reputation.org_allowlist" // R-03
	IDDomainListed = "reputation.domain_listed" // D-02 / R-02
	IDIPListed     = "reputation.ip_listed"     // R-01
	IDDomainAge    = "reputation.domain_age"    // D-01
)

// Register adds reputation checks.
func Register(r *signals.Registry) {
	r.Register(
		signals.NewFunc(IDOrgBlocklist, domain.CategoryReputation, orgLists),
		signals.NewFunc(IDDomainListed, domain.CategoryReputation, domainListed),
		signals.NewFunc(IDIPListed, domain.CategoryReputation, ipListed),
		signals.NewFunc(IDDomainAge, domain.CategoryReputation, domainAge),
	)
}
