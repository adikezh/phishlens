// Package brands loads data/brands.yaml and detects which brand a message
// belongs to or imitates (ТЗ §4.3): by sender domain, by link domains
// (typosquat / homoglyph / Damerau–Levenshtein ≤ 2) and by keywords.
// Logo pHash and colour matching are TODO(F-4.3.2).
package brands

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/netutil"
	"github.com/phishlens/phishlens/internal/similarity"
)

// Brand is one entry of brands.yaml (or a custom org brand, F-4.3.4).
type Brand struct {
	Name       string   `yaml:"name" json:"name"`
	Domains    []string `yaml:"domains" json:"domains"`
	ESPDomains []string `yaml:"esp_domains" json:"esp_domains,omitempty"`
	Keywords   []string `yaml:"keywords" json:"keywords,omitempty"`
	Locale     string   `yaml:"locale" json:"locale,omitempty"`
	Colors     []string `yaml:"colors" json:"colors,omitempty"`
	LogoPHash  string   `yaml:"logo_phash" json:"logo_phash,omitempty"`
	OrgID      string   `yaml:"-" json:"org_id,omitempty"` // "" = global
}

type file struct {
	Brands []Brand `yaml:"brands"`
}

// Load decodes brands.yaml.
func Load(r io.Reader) ([]Brand, error) {
	var f file
	if err := yaml.NewDecoder(r).Decode(&f); err != nil {
		return nil, fmt.Errorf("brands: decode: %w", err)
	}
	for i := range f.Brands {
		f.Brands[i].normalize()
	}
	return f.Brands, nil
}

func (b *Brand) normalize() {
	b.Name = strings.TrimSpace(b.Name)
	lower := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, s := range in {
			if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	b.Domains = lower(b.Domains)
	b.ESPDomains = lower(b.ESPDomains)
	b.Keywords = lower(b.Keywords)
}

// labels are the brand's distinctive tokens: name words ≥ 4 chars and the SLD of each domain.
func (b *Brand) labels() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(s)
		if len([]rune(s)) >= 4 && !seen[s] && !stopLabel[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, w := range strings.Fields(strings.ToLower(b.Name)) {
		add(w)
	}
	for _, d := range b.Domains {
		if ls := netutil.Labels(netutil.RegistrableDomain(d)); len(ls) > 0 {
			add(ls[0])
		}
	}
	return out
}

// stopLabel are brand tokens too generic to indicate imitation on their own.
var stopLabel = map[string]bool{"bank": true, "mail": true, "cloud": true, "live": true, "meta": true, "post": true, "pay": true, "group": true, "kazakhstan": true, "national": true}

// Matcher answers brand questions; safe for concurrent use.
type Matcher struct {
	mu         sync.RWMutex
	brands     []Brand
	homoglyphs map[rune]rune
}

// NewMatcher builds a matcher.
func NewMatcher(list []Brand, homoglyphs map[rune]rune) *Matcher {
	m := &Matcher{homoglyphs: homoglyphs}
	for _, b := range list {
		m.Add(b)
	}
	return m
}

// Add registers a brand (used for custom org brands, F-4.3.4).
func (m *Matcher) Add(b Brand) {
	b.normalize()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.brands {
		if strings.EqualFold(m.brands[i].Name, b.Name) && m.brands[i].OrgID == b.OrgID {
			m.brands[i] = b
			return
		}
	}
	m.brands = append(m.brands, b)
}

// Brands returns a copy sorted by name.
func (m *Matcher) Brands() []Brand {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := append([]Brand(nil), m.brands...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns a brand by name.
func (m *Matcher) Get(name string) (Brand, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.brands {
		if strings.EqualFold(b.Name, name) {
			return b, true
		}
	}
	return Brand{}, false
}

// IsOfficial implements signals.BrandLookup.
func (m *Matcher) IsOfficial(brand, host string) bool {
	b, ok := m.Get(brand)
	if !ok {
		return false
	}
	return b.owns(host)
}

func (b *Brand) owns(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	for _, list := range [][]string{b.Domains, b.ESPDomains} {
		for _, d := range list {
			if host == d || strings.HasSuffix(host, "."+d) {
				return true
			}
		}
	}
	return false
}

// MatchDomain implements signals.BrandLookup: official → (name, true, "domain", 1);
// lookalike → (name, false, "typosquat"|"homoglyph"|"domain_similarity", score).
func (m *Matcher) MatchDomain(host string) (string, bool, string, float64) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return "", false, "", 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.brands {
		if m.brands[i].owns(host) {
			return m.brands[i].Name, true, "domain", 1
		}
	}
	normalized := similarity.NormalizeHomoglyphs(host, m.homoglyphs)
	homoglyphChanged := normalized != host
	labels := netutil.Labels(normalized)
	reg := netutil.RegistrableDomain(normalized)
	sld := ""
	if ls := netutil.Labels(reg); len(ls) > 0 {
		sld = ls[0]
	}
	bestName, bestMethod, bestScore := "", "", 0.0
	for i := range m.brands {
		b := &m.brands[i]
		for _, bl := range b.labels() {
			// exact token inside a foreign domain: kaspi-bank-kz.com, halyk.secure-login.ru
			if similarity.ContainsToken(labels, bl) {
				method := "typosquat"
				if homoglyphChanged {
					method = "homoglyph"
				}
				if 0.95 > bestScore {
					bestName, bestMethod, bestScore = b.Name, method, 0.95
				}
				continue
			}
			if len([]rune(sld)) < 5 || len([]rune(bl)) < 5 {
				continue
			}
			// short labels tolerate one edit, long ones two ("bank" vs "eubank" must not match)
			maxDist := 1
			if len([]rune(bl)) >= 8 {
				maxDist = 2
			}
			if d := similarity.DamerauLevenshtein(sld, bl); d > 0 && d <= maxDist {
				score := 1 - float64(d)/float64(len([]rune(bl)))
				method := "domain_similarity"
				if homoglyphChanged {
					method = "homoglyph"
				}
				if score > bestScore {
					bestName, bestMethod, bestScore = b.Name, method, score
				}
			}
		}
	}
	if bestName == "" {
		return "", false, "", 0
	}
	return bestName, false, bestMethod, bestScore
}

// MatchText finds the brand most referenced by keywords in subject/body.
func (m *Matcher) MatchText(subject, body string) (string, float64) {
	text := strings.ToLower(subject + "\n" + body)
	if strings.TrimSpace(text) == "" {
		return "", 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	bestName, bestHits := "", 0
	for i := range m.brands {
		hits := 0
		for _, kw := range m.brands[i].Keywords {
			if kw != "" && strings.Contains(text, kw) {
				hits++
			}
		}
		if hits > bestHits {
			bestName, bestHits = m.brands[i].Name, hits
		}
	}
	if bestHits == 0 {
		return "", 0
	}
	return bestName, min(1, float64(bestHits)/2)
}

// Match decides which brand a message belongs to / imitates (F-4.3.2).
// Order: sender domain (official or lookalike) → link lookalike → keywords.
func (m *Matcher) Match(mail *domain.ParsedMail) *domain.BrandMatch {
	if mail == nil {
		return nil
	}
	if name, official, method, score := m.MatchDomain(mail.From.Domain); name != "" {
		return &domain.BrandMatch{Name: name, Method: method, Score: score, Official: official}
	}
	for _, host := range mail.LinkDomains() {
		if name, official, method, score := m.MatchDomain(host); name != "" && !official {
			return &domain.BrandMatch{Name: name, Method: "link_" + method, Score: score, Official: m.IsOfficial(name, mail.From.Domain)}
		}
	}
	if name, score := m.MatchText(mail.Subject, mail.Text()); name != "" {
		return &domain.BrandMatch{Name: name, Method: "keyword", Score: score, Official: m.IsOfficial(name, mail.From.Domain)}
	}
	return nil
}
