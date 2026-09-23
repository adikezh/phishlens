// Package authcheck performs the optional local H-04 authentication checks
// when a message has no trusted Authentication-Results header.
package authcheck

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"

	"github.com/phishlens/phishlens/internal/domain"
)

// Resolver is the subset of net.Resolver used by SPF and DMARC.
type Resolver interface {
	LookupTXT(context.Context, string) ([]string, error)
	LookupMX(context.Context, string) ([]*net.MX, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupAddr(context.Context, string) ([]string, error)
}

// NewResolver returns a resolver optionally pinned to host:port (for example
// the configured DNS-over-UDP endpoint). Empty address uses the system DNS.
func NewResolver(address string) Resolver {
	if address == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, address)
		},
	}
}

// Verify performs bounded, read-only SPF/DKIM/DMARC checks. Unknown or
// unavailable DNS data is represented as an unknown result; it never becomes
// a positive authentication result.
func Verify(ctx context.Context, mail *domain.ParsedMail, resolver Resolver) (domain.AuthResults, error) {
	if mail == nil || mail.From.Domain == "" {
		return domain.AuthResults{Source: "own"}, nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	out := domain.AuthResults{Source: "own"}
	spfDomain := mail.ReturnPath.Domain
	if spfDomain == "" {
		spfDomain = mail.From.Domain
	}
	if ip := firstExternalIP(mail.Received); ip != nil {
		sender := mail.ReturnPath.Addr
		if sender == "" {
			sender = mail.From.Addr
		}
		helo := mail.From.Domain
		if len(mail.Received) > 0 && mail.Received[0].From != "" {
			helo = mail.Received[0].From
		}
		result, err := spf.CheckHostWithSender(ip, helo, sender,
			spf.WithContext(ctx), spf.WithResolver(resolver))
		if err != nil && result == "" {
			return out, fmt.Errorf("spf lookup: %w", err)
		}
		out.SPF = mapSPF(result)
	}

	if len(mail.Raw) > 0 && mail.Header("DKIM-Signature") != "" {
		verifications, err := dkim.VerifyWithOptions(bytes.NewReader(mail.Raw), &dkim.VerifyOptions{
			LookupTXT: func(name string) ([]string, error) {
				return resolver.LookupTXT(ctx, name)
			},
			MaxVerifications: 5,
		})
		if err != nil && len(verifications) == 0 {
			// A malformed signature is a permanent authentication failure; DNS
			// failures are left unknown so a transient outage cannot score as phish.
			if dkim.IsPermFail(err) {
				out.DKIM = domain.AuthPermError
			}
		} else {
			out.DKIM = domain.AuthFail
			for _, verification := range verifications {
				if verification != nil && verification.Err == nil {
					out.DKIM = domain.AuthPass
					break
				}
			}
		}
	} else {
		out.DKIM = domain.AuthNone
	}

	policy, policyDomain, err := lookupDMARC(ctx, resolver, mail.From.Domain)
	if err != nil {
		return out, fmt.Errorf("dmarc lookup: %w", err)
	}
	if len(policy) == 0 {
		out.DMARC = domain.AuthNone
		return out, nil
	}

	// DMARC alignment is evaluated conservatively. SPF uses the envelope
	// sender; DKIM alignment is checked from the verified signature domain.
	spfAligned := out.SPF == domain.AuthPass && aligned(spfDomain, mail.From.Domain, policy["aspf"] == "s")
	dkimAligned := false
	if out.DKIM == domain.AuthPass {
		// Verify again only to obtain the authenticated signing domain. This is
		// intentionally bounded and uses the same DNS resolver.
		verifications, _ := dkim.VerifyWithOptions(bytes.NewReader(mail.Raw), &dkim.VerifyOptions{
			LookupTXT: func(name string) ([]string, error) {
				return resolver.LookupTXT(ctx, name)
			},
			MaxVerifications: 5,
		})
		for _, verification := range verifications {
			if verification != nil && verification.Err == nil && aligned(verification.Domain, mail.From.Domain, policy["adkim"] == "s") {
				dkimAligned = true
				break
			}
		}
	}
	if spfAligned || dkimAligned {
		out.DMARC = domain.AuthPass
	} else {
		out.DMARC = domain.AuthFail
	}
	_ = policyDomain // retained for diagnostics and future p/sp enforcement
	return out, nil
}

func mapSPF(result spf.Result) domain.AuthResult {
	switch result {
	case spf.Pass:
		return domain.AuthPass
	case spf.Fail:
		return domain.AuthFail
	case spf.SoftFail:
		return domain.AuthSoftFail
	case spf.Neutral:
		return domain.AuthNeutral
	case spf.TempError:
		return domain.AuthTempError
	case spf.PermError:
		return domain.AuthPermError
	default:
		return domain.AuthNone
	}
}

func firstExternalIP(hops []domain.ReceivedHop) net.IP {
	for _, hop := range hops {
		ip := net.ParseIP(hop.IP)
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		return ip
	}
	return nil
}

func lookupDMARC(ctx context.Context, resolver Resolver, domainName string) (map[string]string, string, error) {
	for _, candidate := range []string{"_dmarc." + strings.TrimSuffix(domainName, "."), "_dmarc." + organizationalDomain(domainName)} {
		txts, err := resolver.LookupTXT(ctx, candidate)
		if err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, "", err
		}
		tags := parseTags(strings.Join(txts, ""))
		if strings.EqualFold(tags["v"], "DMARC1") {
			return tags, strings.TrimPrefix(candidate, "_dmarc."), nil
		}
	}
	return nil, "", nil
}

func parseTags(record string) map[string]string {
	tags := map[string]string{}
	for _, item := range strings.Split(record, ";") {
		parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(parts) == 2 {
			tags[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		}
	}
	return tags
}

func aligned(left, right string, strict bool) bool {
	left, right = strings.TrimSuffix(strings.ToLower(left), "."), strings.TrimSuffix(strings.ToLower(right), ".")
	if strict {
		return left == right
	}
	return left == right || strings.HasSuffix(left, "."+right) || strings.HasSuffix(right, "."+left)
}

func organizationalDomain(name string) string {
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	if len(parts) <= 2 {
		return strings.Join(parts, ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsNotFound
	}
	return false
}
