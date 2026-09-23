// Package header implements header heuristics H-01 … H-08 (ТЗ §4.2).
// One file per heuristic; docs in docs/signals/header.*.md.
package header

import (
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

// Signal IDs.
const (
	IDDisplayNameEmail   = "header.displayname_email"   // H-01
	IDReplyToMismatch    = "header.replyto_mismatch"    // H-02
	IDReturnPathMismatch = "header.returnpath_mismatch" // H-03
	IDMessageIDMismatch  = "header.messageid_mismatch"  // H-06
	IDMessageIDMissing   = "header.messageid_missing"   // H-06
	IDDateSkew           = "header.date_skew"           // H-08
)

// Register adds all header checks to r.
func Register(r *signals.Registry) {
	r.Register(
		signals.NewFunc(IDDisplayNameEmail, domain.CategoryHeader, displayNameEmail),
		signals.NewFunc(IDReplyToMismatch, domain.CategoryHeader, replyToMismatch),
		signals.NewFunc(IDReturnPathMismatch, domain.CategoryHeader, returnPathMismatch),
		signals.NewFunc(IDMessageIDMismatch, domain.CategoryHeader, messageID),
		signals.NewFunc(IDDateSkew, domain.CategoryHeader, dateSkew),
	)
	// TODO(H-05): Received chain IP in TI / geography mismatch — needs reputation stage.
	// TODO(H-07): X-Mailer / User-Agent of bulk mailers on a personal-looking message.
}
