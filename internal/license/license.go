// Package license distinguishes Community from Business features (ТЗ §1.3).
// Business keys are Ed25519-signed compact JSON payloads.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"time"
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
	Edition   Edition
	Org       string
	ExpiresAt time.Time
	Features  map[string]bool
}

// Load reads PL_LICENSE_KEY; without a key the edition is Community.
func Load() *License {
	key := strings.TrimSpace(os.Getenv("PL_LICENSE_KEY"))
	community := func() *License { return &License{Edition: Community, Features: map[string]bool{}} }
	if key == "" {
		return community()
	}
	pub, ok := decodeKey(os.Getenv("PL_LICENSE_PUBLIC_KEY"))
	if !ok || len(pub) != ed25519.PublicKeySize {
		return community()
	}
	parts := strings.Split(key, ".")
	if len(parts) != 2 {
		return community()
	}
	payload, err := decodeBase64(parts[0])
	if err != nil {
		return community()
	}
	sig, err := decodeBase64(parts[1])
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return community()
	}
	var c claims
	if json.Unmarshal(payload, &c) != nil || c.Edition != Business || c.Org == "" {
		return community()
	}
	var expiry time.Time
	if c.ExpiresAt != "" {
		expiry, err = time.Parse(time.RFC3339, c.ExpiresAt)
		if err != nil || !expiry.After(time.Now().UTC()) {
			return community()
		}
	}
	return &License{Edition: c.Edition, Org: c.Org, ExpiresAt: expiry, Features: c.Features}
}

type claims struct {
	Edition   Edition         `json:"edition"`
	Org       string          `json:"org"`
	ExpiresAt string          `json:"expires_at,omitempty"`
	Features  map[string]bool `json:"features"`
}

func decodeBase64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
}

func decodeKey(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if b, err := decodeBase64(s); err == nil {
		return b, true
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

// Has reports whether a feature is unlocked.
func (l *License) Has(feature string) bool {
	return l != nil && l.Edition == Business && (l.ExpiresAt.IsZero() || time.Now().UTC().Before(l.ExpiresAt)) && l.Features[feature]
}
