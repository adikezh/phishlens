// Package signals defines the heuristic contract: every check receives an Input
// and returns zero or more domain.Signal. One directory per category, one file
// per heuristic (ТЗ §4.2); each category exposes Register(*Registry).
package signals

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/i18n"
	"github.com/phishlens/phishlens/internal/refdata"
)

// BrandLookup is implemented by brands.Matcher (kept as an interface to avoid a
// signals → brands dependency).
type BrandLookup interface {
	// MatchDomain classifies a host against the brand base.
	MatchDomain(host string) (name string, official bool, method string, score float64)
	// IsOfficial reports whether host belongs to brand's official/ESP domains.
	IsOfficial(brand, host string) bool
}

// ListLookup answers organisation allow/block list questions (R-03).
type ListLookup interface {
	IsAllowed(ctx context.Context, value string) (bool, string)
	IsBlocked(ctx context.Context, value string) (bool, string)
}

// ReputationLookup abstracts DNSBL / TI / RDAP clients (R-01, R-02, D-01).
type ReputationLookup interface {
	IPListed(ctx context.Context, ip string) (listed bool, source string, err error)
	DomainListed(ctx context.Context, domain string) (listed bool, source string, err error)
	DomainAge(ctx context.Context, domain string) (age time.Duration, known bool, err error)
}

// Input is everything a check may look at.
type Input struct {
	Mail   *domain.ParsedMail
	Brand  *domain.BrandMatch
	Lang   string
	OrgID  string
	Data   *refdata.Data
	Brands BrandLookup
	Lists  ListLookup
	Rep    ReputationLookup
	LLM    *domain.LLMExplain // set before the semantic stage
}

// Check is one heuristic.
type Check interface {
	ID() string
	Category() domain.Category
	Run(ctx context.Context, in *Input) ([]domain.Signal, error)
}

// Func adapts a plain function to Check.
type Func struct {
	id  string
	cat domain.Category
	fn  func(ctx context.Context, in *Input) ([]domain.Signal, error)
}

// NewFunc wraps fn as a Check.
func NewFunc(id string, cat domain.Category, fn func(ctx context.Context, in *Input) ([]domain.Signal, error)) Check {
	return &Func{id: id, cat: cat, fn: fn}
}

func (f *Func) ID() string                { return f.id }
func (f *Func) Category() domain.Category { return f.cat }
func (f *Func) Run(ctx context.Context, in *Input) ([]domain.Signal, error) {
	return f.fn(ctx, in)
}

// New builds a Signal with a localised explanation (key = signal id).
func New(id string, cat domain.Category, weight int, confidence float64, evidence, lang string, args ...any) domain.Signal {
	if confidence <= 0 {
		confidence = 1
	}
	if confidence > 1 {
		confidence = 1
	}
	return domain.Signal{
		ID:          id,
		Category:    cat,
		Weight:      weight,
		Confidence:  confidence,
		Evidence:    Truncate(evidence, 300),
		Explanation: i18n.T(lang, id, args...),
		Source:      domain.SourceHeuristic,
	}
}

// Truncate shortens evidence for storage/UI.
func Truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// Registry holds registered checks.
type Registry struct {
	mu     sync.RWMutex
	checks []Check
	byID   map[string]Check
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: map[string]Check{}}
}

// Register adds checks; duplicate IDs panic (programming error).
func (r *Registry) Register(checks ...Check) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range checks {
		if _, dup := r.byID[c.ID()]; dup {
			panic(fmt.Sprintf("signals: duplicate check id %q", c.ID()))
		}
		r.byID[c.ID()] = c
		r.checks = append(r.checks, c)
	}
}

// Checks returns registered checks sorted by ID.
func (r *Registry) Checks() []Check {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := append([]Check(nil), r.checks...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Len returns the number of registered checks.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.checks)
}

// RunError wraps a failing check without aborting the stage (degradation, ТЗ §5).
type RunError struct {
	CheckID string
	Err     error
}

func (e *RunError) Error() string { return e.CheckID + ": " + e.Err.Error() }
func (e *RunError) Unwrap() error { return e.Err }

// RunCategories executes every check of the given categories sequentially and
// returns all signals plus per-check errors. A panic inside a check is
// converted to an error.
func (r *Registry) RunCategories(ctx context.Context, in *Input, cats ...domain.Category) ([]domain.Signal, []error) {
	want := map[domain.Category]bool{}
	for _, c := range cats {
		want[c] = true
	}
	var out []domain.Signal
	var errs []error
	for _, c := range r.Checks() {
		if len(want) > 0 && !want[c.Category()] {
			continue
		}
		if ctx.Err() != nil {
			errs = append(errs, &RunError{CheckID: c.ID(), Err: ctx.Err()})
			break
		}
		sigs, err := safeRun(ctx, c, in)
		if err != nil {
			errs = append(errs, &RunError{CheckID: c.ID(), Err: err})
			continue
		}
		out = append(out, sigs...)
	}
	return out, errs
}

func safeRun(ctx context.Context, c Check, in *Input) (sigs []domain.Signal, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("panic: %v", rec)
		}
	}()
	return c.Run(ctx, in)
}

// ErrSkipped can be returned by a check that cannot run (missing dependency);
// it is reported as a warning, not an error.
var ErrSkipped = errors.New("skipped")
