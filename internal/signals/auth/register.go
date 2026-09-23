// Package auth implements H-04: SPF / DKIM / DMARC outcomes from the
// Authentication-Results header, plus the −40 "aligned official brand" rule (F-4.5.3).
//
// TODO(H-04): own checks when the header is absent (auth_checks.own_spf_dkim_dmarc):
// SPF via blitiri.com.ar/go/spf on the first Received IP, DKIM via emersion/go-msgauth,
// DMARC policy lookup via miekg/dns. Results must set AuthResults.Source = "own".
package auth

import (
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

const (
	IDSPFFail         = "auth.spf_fail"
	IDSPFSoftFail     = "auth.spf_softfail"
	IDDKIMFail        = "auth.dkim_fail"
	IDDKIMNone        = "auth.dkim_none"
	IDDMARCFail       = "auth.dmarc_fail"
	IDUnverified      = "auth.unverified"
	IDAlignedOfficial = "auth.aligned_official"
)

// Register adds auth checks.
func Register(r *signals.Registry) {
	r.Register(
		signals.NewFunc(IDSPFFail, domain.CategoryAuth, spf),
		signals.NewFunc(IDDKIMFail, domain.CategoryAuth, dkim),
		signals.NewFunc(IDDMARCFail, domain.CategoryAuth, dmarc),
		signals.NewFunc(IDUnverified, domain.CategoryAuth, unverified),
		signals.NewFunc(IDAlignedOfficial, domain.CategoryAuth, alignedOfficial),
	)
}
