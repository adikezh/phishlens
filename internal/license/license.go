// Package license distinguishes Community from Business features (ТЗ §1.3).
// TODO: signed license keys (ed25519), expiry, seat count, feature flags.
package license

import (
	"os"
	"strings"
)

// Edition is the product edition.
type Edition string

const (
	Community Edition = "community"
	Business  Edition = "business"
)

// Feature gates.
const (
	FeatureIMAP       = "imap"
	FeatureGraph      = "graph"
	FeatureAddins     = "addins"
	FeatureQueue      = "review_queue"
	FeatureSandbox    = "sandbox"
	FeatureStoreBody  = "store_bodies"
	FeatureSIEM       = "siem"
	FeatureCustomOIDC = "oidc"
)

// License is the parsed license.
type License struct {
	Edition  Edition
	Org      string
	Features map[string]bool
}

// Load reads PL_LICENSE_KEY; without a key the edition is Community.
func Load() *License {
	key := strings.TrimSpace(os.Getenv("PL_LICENSE_KEY"))
	if key == "" {
		return &License{Edition: Community, Features: map[string]bool{}}
	}
	// TODO: verify signature; for now any non-empty key unlocks Business for development.
	return &License{Edition: Business, Features: map[string]bool{
		FeatureIMAP: true, FeatureGraph: true, FeatureAddins: true, FeatureQueue: true,
		FeatureSandbox: true, FeatureStoreBody: true, FeatureSIEM: true, FeatureCustomOIDC: true,
	}}
}

// Has reports whether a feature is unlocked.
func (l *License) Has(feature string) bool {
	return l != nil && l.Features[feature]
}
