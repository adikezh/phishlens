// Package domainsig implements sender-domain heuristics D-03 … D-06 (ТЗ §4.2).
// D-01 (registration age) and D-02 (TI lists) live in the reputation category
// because they need network lookups.
package domainsig

import (
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

const (
	IDPunycode       = "domain.punycode"        // D-03
	IDMixedScript    = "domain.mixed_script"    // D-03
	IDBrandLookalike = "domain.brand_lookalike" // D-04
	IDFreeMailOrg    = "domain.free_mail_org"   // D-05
	IDRiskyTLD       = "domain.risky_tld"       // D-06
)

// Register adds domain checks.
func Register(r *signals.Registry) {
	r.Register(
		signals.NewFunc(IDPunycode, domain.CategoryDomain, punycodeMixed),
		signals.NewFunc(IDBrandLookalike, domain.CategoryDomain, brandLookalike),
		signals.NewFunc(IDFreeMailOrg, domain.CategoryDomain, freeMailOrg),
		signals.NewFunc(IDRiskyTLD, domain.CategoryDomain, riskyTLD),
	)
}
