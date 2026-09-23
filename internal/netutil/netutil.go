// Package netutil holds small host/IP helpers shared by parse, signals and reputation.
package netutil

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// RegistrableDomain returns eTLD+1 ("mail.kaspi.kz" → "kaspi.kz"). Falls back to the
// input when the public-suffix list cannot resolve it (IPs, single labels).
func RegistrableDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || net.ParseIP(host) != nil {
		return host
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// TLD returns the last label of a host without the dot ("kaspi.kz" → "kz").
func TLD(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if i := strings.LastIndex(host, "."); i >= 0 {
		return host[i+1:]
	}
	return ""
}

// SameRegistrable reports whether two hosts share eTLD+1 (case-insensitive).
func SameRegistrable(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return RegistrableDomain(a) == RegistrableDomain(b)
}

// Labels splits a host into lowercase labels by "." and "-" ("kaspi-bank-kz.com" → kaspi bank kz com).
func Labels(host string) []string {
	host = strings.ToLower(host)
	return strings.FieldsFunc(host, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
}

// IsPrivateOrLocal reports whether ip must never be contacted by link expansion /
// sandbox (SSRF protection, ТЗ §11): RFC1918, loopback, link-local, ULA, metadata.
func IsPrivateOrLocal(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// cloud metadata endpoints
	if ip.Equal(net.ParseIP("169.254.169.254")) || ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return true
	}
	return false
}
