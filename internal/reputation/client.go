// Package reputation implements signals.ReputationLookup: DNSBL, OpenPhish and
// RDAP are available; URLhaus requires its configured Auth-Key. AbuseIPDB, Safe
// Browsing and VirusTotal remain optional integrations. Provider failures degrade
// to "unknown" and never create a positive signal.
package reputation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/store"
)

// ErrNotImplemented marks stubbed sources.
var ErrNotImplemented = errors.New("reputation: not implemented")

// Client aggregates sources.
type Client struct {
	cfg             config.Reputation
	resolver        *net.Resolver
	cache           *ttlCache
	log             zerolog.Logger
	local           map[string]struct{} // local domain blocklist (from data/ or org)
	http            *http.Client
	safeBrowsingURL string
	abuseIPDBURL    string
	virusTotalURL   string
	breakers        map[string]*circuitBreaker
	breakerMu       sync.Mutex
	store           PersistentCache
}

// PersistentCache is implemented by store.Store without coupling provider
// code to a particular database driver.
type PersistentCache interface {
	GetReputationCache(context.Context, string) (*store.ReputationCacheEntry, error)
	PutReputationCache(context.Context, string, string, time.Time) error
}

// New builds a client; dnsResolver is "host:port" or "" for the system resolver.
func New(cfg config.Reputation, dnsResolver string, log zerolog.Logger) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	c := &Client{
		cfg: cfg, cache: newTTLCache(), log: log, local: map[string]struct{}{},
		http:            &http.Client{Timeout: timeout},
		safeBrowsingURL: "https://safebrowsing.googleapis.com/v4/threatMatches:find",
		abuseIPDBURL:    "https://api.abuseipdb.com/api/v2/check",
		virusTotalURL:   "https://www.virustotal.com/api/v3/files",
		breakers:        map[string]*circuitBreaker{},
	}
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

func (c *Client) allowProvider(name string) error {
	c.breakerMu.Lock()
	defer c.breakerMu.Unlock()
	b := c.breakers[name]
	if b == nil {
		b = newCircuitBreaker(3, 30*time.Second)
		c.breakers[name] = b
	}
	if !b.allow(time.Now()) {
		return circuitError(name)
	}
	return nil
}

func (c *Client) observeProvider(name string, err error) {
	c.breakerMu.Lock()
	b := c.breakers[name]
	c.breakerMu.Unlock()
	if b != nil {
		b.observe(time.Now(), err)
	}
}

// SetPersistentCache attaches the already-migrated application store. Cache
// values contain provider responses only; no message bodies or user identity.
func (c *Client) SetPersistentCache(cache PersistentCache) { c.store = cache }

func (c *Client) getListCache(ctx context.Context, key string) (listResult, bool) {
	if v, ok := c.cache.get(key); ok {
		return v.(listResult), true
	}
	if c.store == nil {
		return listResult{}, false
	}
	entry, err := c.store.GetReputationCache(ctx, key)
	if err != nil {
		return listResult{}, false
	}
	var persisted struct {
		Listed bool   `json:"listed"`
		Source string `json:"source"`
	}
	if json.Unmarshal([]byte(entry.Value), &persisted) != nil {
		return listResult{}, false
	}
	result := listResult{listed: persisted.Listed, source: persisted.Source}
	c.cache.set(key, result, time.Until(entry.ExpiresAt))
	return result, true
}

func (c *Client) setListCache(ctx context.Context, key string, result listResult, ttl time.Duration) {
	c.cache.set(key, result, ttl)
	if c.store != nil {
		value, err := json.Marshal(struct {
			Listed bool   `json:"listed"`
			Source string `json:"source"`
		}{Listed: result.listed, Source: result.source})
		if err == nil {
			_ = c.store.PutReputationCache(ctx, key, string(value), time.Now().Add(ttl))
		}
	}
}

func (c *Client) getAgeCache(ctx context.Context, key string) (time.Duration, bool) {
	if v, ok := c.cache.get(key); ok {
		return v.(time.Duration), true
	}
	if c.store == nil {
		return 0, false
	}
	entry, err := c.store.GetReputationCache(ctx, key)
	if err != nil {
		return 0, false
	}
	var age time.Duration
	if json.Unmarshal([]byte(entry.Value), &age) != nil {
		return 0, false
	}
	c.cache.set(key, age, time.Until(entry.ExpiresAt))
	return age, true
}

func (c *Client) setAgeCache(ctx context.Context, key string, age, ttl time.Duration) {
	c.cache.set(key, age, ttl)
	if c.store != nil {
		if value, err := json.Marshal(age); err == nil {
			_ = c.store.PutReputationCache(ctx, key, string(value), time.Now().Add(ttl))
		}
	}
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
	if parsed == nil {
		return false, "", nil
	}
	if parsed.IsPrivate() || parsed.IsLoopback() {
		return false, "", nil
	}
	key := "dnsbl:" + ip
	if r, ok := c.getListCache(ctx, key); ok {
		return r.listed, r.source, nil
	}
	var lastErr error
	if err := c.allowProvider("dnsbl"); err != nil {
		lastErr = err
	} else {
		rev := reverseIP(parsed)
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
					c.observeProvider("dnsbl", nil)
					c.setListCache(ctx, key, listResult{true, zone}, 6*time.Hour)
					return true, zone, nil
				}
			}
		}
		c.observeProvider("dnsbl", lastErr)
	}
	if c.cfg.AbuseIPDB.Enabled {
		var listed bool
		var err error
		if breakerErr := c.allowProvider("abuseipdb"); breakerErr != nil {
			err = breakerErr
		} else {
			listed, err = abuseIPDBLookup(ctx, c.http, c.abuseIPDBURL, ip, os.Getenv(c.cfg.AbuseIPDB.KeyEnv))
			c.observeProvider("abuseipdb", err)
		}
		if err == nil && listed {
			c.setListCache(ctx, key, listResult{true, "abuseipdb"}, 6*time.Hour)
			return true, "abuseipdb", nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		return false, "", fmt.Errorf("dnsbl: %w", lastErr)
	}
	c.setListCache(ctx, key, listResult{false, ""}, 6*time.Hour)
	return false, "", nil
}

// DomainListed checks the local list, then enabled TI feeds (R-02 / D-02).
func (c *Client) DomainListed(ctx context.Context, domain string) (bool, string, error) {
	domain = strings.ToLower(domain)
	if _, ok := c.local[domain]; ok {
		return true, "local", nil
	}
	key := "domain-listed:" + domain
	if r, ok := c.getListCache(ctx, key); ok {
		return r.listed, r.source, nil
	}
	providerError := false
	if c.cfg.URLhaus.Enabled {
		var listed bool
		var err error
		if breakerErr := c.allowProvider("urlhaus"); breakerErr != nil {
			err = breakerErr
		} else {
			listed, err = urlhausLookup(ctx, domain, os.Getenv(c.cfg.URLhaus.AuthKeyEnv))
			c.observeProvider("urlhaus", err)
		}
		if err == nil && listed {
			c.setListCache(ctx, key, listResult{true, "urlhaus"}, 12*time.Hour)
			return true, "urlhaus", nil
		} else if err != nil {
			providerError = true
		}
	}
	if c.cfg.OpenPhish.Enabled {
		var listed bool
		var err error
		if breakerErr := c.allowProvider("openphish"); breakerErr != nil {
			err = breakerErr
		} else {
			listed, err = openphishLookup(ctx, domain)
			c.observeProvider("openphish", err)
		}
		if err == nil && listed {
			c.setListCache(ctx, key, listResult{true, "openphish"}, 12*time.Hour)
			return true, "openphish", nil
		} else if err != nil {
			providerError = true
		}
	}
	if c.cfg.SafeBrowsing.Enabled {
		var listed bool
		var err error
		if breakerErr := c.allowProvider("safebrowsing"); breakerErr != nil {
			err = breakerErr
		} else {
			listed, err = safeBrowsingLookup(ctx, c.http, c.safeBrowsingURL, domain, os.Getenv(c.cfg.SafeBrowsing.APIKeyEnv))
			c.observeProvider("safebrowsing", err)
		}
		if err == nil && listed {
			c.setListCache(ctx, key, listResult{true, "safebrowsing"}, 12*time.Hour)
			return true, "safebrowsing", nil
		}
		if err != nil {
			providerError = true
		}
	}
	if !providerError {
		c.setListCache(ctx, key, listResult{false, ""}, 6*time.Hour)
	}
	return false, "", nil
}

// FileHashListed checks VirusTotal by hash only. The file bytes are never sent.
func (c *Client) FileHashListed(ctx context.Context, sha256 string) (bool, string, error) {
	if !c.cfg.VirusTotal.Enabled || !c.cfg.VirusTotal.AttachmentsOnly || !isSHA256(sha256) {
		return false, "", nil
	}
	var listed bool
	var err error
	if breakerErr := c.allowProvider("virustotal"); breakerErr != nil {
		err = breakerErr
	} else {
		listed, err = virusTotalLookup(ctx, c.http, c.virusTotalURL, sha256, os.Getenv(c.cfg.VirusTotal.KeyEnv))
		c.observeProvider("virustotal", err)
	}
	if err != nil {
		return false, "", err
	}
	if listed {
		return true, "virustotal", nil
	}
	return false, "", nil
}

// DomainAge returns the registration age via RDAP (D-01).
func (c *Client) DomainAge(ctx context.Context, domain string) (time.Duration, bool, error) {
	if !c.cfg.RDAP.Enabled {
		return 0, false, nil
	}
	key := "rdap:" + domain
	if age, ok := c.getAgeCache(ctx, key); ok {
		return age, true, nil
	}
	if err := c.allowProvider("rdap"); err != nil {
		return 0, false, nil
	}
	age, err := rdapAge(ctx, domain)
	c.observeProvider("rdap", err)
	if err != nil {
		// Provider outages, rate limits, and incomplete registry data are an
		// unavailable signal, never a reason to fail or add a positive score.
		return 0, false, nil
	}
	ttl := c.cfg.RDAP.CacheTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	c.setAgeCache(ctx, key, age, ttl)
	return age, true, nil
}

type listResult struct {
	listed bool
	source string
}

func reverse4(ip net.IP) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0])
}

// reverseIP renders the DNSBL query label for either address family. IPv6
// DNSBL zones use all 32 hexadecimal nibbles in reverse order.
func reverseIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return reverse4(v4)
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 0, 63)
	for i := len(v6) - 1; i >= 0; i-- {
		b := v6[i]
		buf = append(buf, hexDigits[b&0x0f], '.')
		buf = append(buf, hexDigits[b>>4], '.')
	}
	return string(buf[:len(buf)-1])
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
