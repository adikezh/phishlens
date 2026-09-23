// Package reputation implements signals.ReputationLookup: DNSBL, OpenPhish and
// RDAP are available; URLhaus requires its configured Auth-Key. AbuseIPDB, Safe
// Browsing and VirusTotal remain optional integrations. Provider failures degrade
// to "unknown" and never create a positive signal.
//
// TODO(§5): sony/gobreaker per external service; persist cache in reputation_cache table.
package reputation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/phishlens/phishlens/internal/config"
)

// ErrNotImplemented marks stubbed sources.
var ErrNotImplemented = errors.New("reputation: not implemented")

// Client aggregates sources.
type Client struct {
	cfg      config.Reputation
	resolver *net.Resolver
	cache    *ttlCache
	log      zerolog.Logger
	local    map[string]struct{} // local domain blocklist (from data/ or org)
}

// New builds a client; dnsResolver is "host:port" or "" for the system resolver.
func New(cfg config.Reputation, dnsResolver string, log zerolog.Logger) *Client {
	c := &Client{cfg: cfg, cache: newTTLCache(), log: log, local: map[string]struct{}{}}
	if dnsResolver != "" {
		c.resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, network, dnsResolver)
			},
		}
	} else {
		c.resolver = net.DefaultResolver
	}
	return c
}

// AddLocalBlock adds a domain to the in-memory local TI list.
func (c *Client) AddLocalBlock(domain string) {
	c.local[strings.ToLower(domain)] = struct{}{}
}

// IPListed queries each configured DNSBL zone (R-01).
func (c *Client) IPListed(ctx context.Context, ip string) (bool, string, error) {
	if len(c.cfg.DNSBL) == 0 {
		return false, "", nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return false, "", nil // TODO: IPv6 nibble format
	}
	if parsed.IsPrivate() || parsed.IsLoopback() {
		return false, "", nil
	}
	key := "dnsbl:" + ip
	if v, ok := c.cache.get(key); ok {
		r := v.(listResult)
		return r.listed, r.source, nil
	}
	rev := reverse4(parsed.To4())
	var lastErr error
	for _, zone := range c.cfg.DNSBL {
		q := rev + "." + strings.TrimSuffix(zone, ".") + "."
		addrs, err := c.resolver.LookupHost(ctx, q)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				continue // not listed
			}
			lastErr = err
			continue
		}
		for _, a := range addrs {
			// DNSBL convention: 127.0.0.x = listed. Spamhaus 127.255.255.x = error
			// (open resolver / query limit / typo) — must not count as listed.
			if strings.HasPrefix(a, "127.255.") {
				lastErr = fmt.Errorf("%s answered %s (blocked resolver or query limit)", zone, a)
				break
			}
			if strings.HasPrefix(a, "127.") {
				c.cache.set(key, listResult{true, zone}, 6*time.Hour)
				return true, zone, nil
			}
		}
	}
	if lastErr != nil {
		return false, "", fmt.Errorf("dnsbl: %w", lastErr)
	}
	c.cache.set(key, listResult{false, ""}, 6*time.Hour)
	return false, "", nil
}

// DomainListed checks the local list, then enabled TI feeds (R-02 / D-02).
func (c *Client) DomainListed(ctx context.Context, domain string) (bool, string, error) {
	domain = strings.ToLower(domain)
	if _, ok := c.local[domain]; ok {
		return true, "local", nil
	}
	key := "domain-listed:" + domain
	if v, ok := c.cache.get(key); ok {
		r := v.(listResult)
		return r.listed, r.source, nil
	}
	providerError := false
	if c.cfg.URLhaus.Enabled {
		if listed, err := urlhausLookup(ctx, domain, os.Getenv(c.cfg.URLhaus.AuthKeyEnv)); err == nil && listed {
			c.cache.set(key, listResult{true, "urlhaus"}, 12*time.Hour)
			return true, "urlhaus", nil
		} else if err != nil {
			providerError = true
		}
	}
	if c.cfg.OpenPhish.Enabled {
		if listed, err := openphishLookup(ctx, domain); err == nil && listed {
			c.cache.set(key, listResult{true, "openphish"}, 12*time.Hour)
			return true, "openphish", nil
		} else if err != nil {
			providerError = true
		}
	}
	if !providerError {
		c.cache.set(key, listResult{false, ""}, 6*time.Hour)
	}
	return false, "", nil
}

// DomainAge returns the registration age via RDAP (D-01).
func (c *Client) DomainAge(ctx context.Context, domain string) (time.Duration, bool, error) {
	if !c.cfg.RDAP.Enabled {
		return 0, false, nil
	}
	key := "rdap:" + domain
	if v, ok := c.cache.get(key); ok {
		return v.(time.Duration), true, nil
	}
	age, err := rdapAge(ctx, domain)
	if err != nil {
		// Provider outages, rate limits, and incomplete registry data are an
		// unavailable signal, never a reason to fail or add a positive score.
		return 0, false, nil
	}
	ttl := c.cfg.RDAP.CacheTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	c.cache.set(key, age, ttl)
	return age, true, nil
}

type listResult struct {
	listed bool
	source string
}

func reverse4(ip net.IP) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0])
}

// ---- tiny TTL cache -------------------------------------------------------

type ttlCache struct {
	mu    sync.Mutex
	items map[string]ttlItem
}

type ttlItem struct {
	v   any
	exp time.Time
}

func newTTLCache() *ttlCache { return &ttlCache{items: map[string]ttlItem{}} }

func (c *ttlCache) get(k string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.items[k]
	if !ok || time.Now().After(it.exp) {
		delete(c.items, k)
		return nil, false
	}
	return it.v, true
}

func (c *ttlCache) set(k string, v any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) > 50000 {
		c.items = map[string]ttlItem{}
	}
	c.items[k] = ttlItem{v: v, exp: time.Now().Add(ttl)}
}
