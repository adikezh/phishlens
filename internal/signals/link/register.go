// Package link implements hyperlink heuristics L-01 … L-08 (ТЗ §4.2).
package link

import (
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/signals"
)

const (
	IDTextHrefMismatch = "link.text_href_mismatch"  // L-01
	IDIPHost           = "link.ip_host"             // L-02
	IDNonstandardPort  = "link.nonstandard_port"    // L-02
	IDShortener        = "link.shortener"           // L-03
	IDObfuscated       = "link.obfuscated"          // L-04
	IDPunycode         = "link.punycode"            // D-03 for links
	IDBrandLookalike   = "link.brand_lookalike"     // D-04 for links
	IDManyDomains      = "link.many_domains"        // L-06
	IDTrackingPixel    = "link.tracking_pixel"      // L-07
	IDMissingUnsub     = "link.missing_unsubscribe" // L-07
	IDLoginForm        = "link.login_form"          // L-05
)

// Register adds link checks.
func Register(r *signals.Registry) {
	r.Register(
		signals.NewFunc(IDTextHrefMismatch, domain.CategoryLink, textHrefMismatch),
		signals.NewFunc(IDIPHost, domain.CategoryLink, ipHost),
		signals.NewFunc(IDShortener, domain.CategoryLink, shortener),
		signals.NewFunc(IDObfuscated, domain.CategoryLink, obfuscated),
		signals.NewFunc(IDPunycode, domain.CategoryLink, punycode),
		signals.NewFunc(IDBrandLookalike, domain.CategoryLink, brandLookalike),
		signals.NewFunc(IDManyDomains, domain.CategoryLink, manyDomains),
		signals.NewFunc(IDTrackingPixel, domain.CategoryLink, trackingPixel),
		signals.NewFunc(IDMissingUnsub, domain.CategoryLink, missingUnsubscribe),
		signals.NewFunc(IDLoginForm, domain.CategoryLink, loginForm),
	)
}
