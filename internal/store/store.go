// Package store persists submissions, analyses, signals, lists, brands, API keys
// and audit records (ТЗ §3). SQLite via modernc (no cgo); Postgres via pgx is
// TODO. Queries are hand-written for the skeleton; sqlc generation is wired in
// sqlc.yaml for later.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/phishlens/phishlens/internal/brands"
	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

var (
	// ErrNotFound is returned for missing rows.
	ErrNotFound = errors.New("store: not found")
	// ErrNotImplemented marks the Postgres driver.
	ErrNotImplemented = errors.New("store: not implemented")
)

// ListKind selects allowlist or blocklist.
type ListKind string

const (
	ListAllow ListKind = "allow"
	ListBlock ListKind = "block"
)

// ListEntry is one allow/block row.
type ListEntry struct {
	OrgID     string    `json:"org_id,omitempty"`
	Kind      ListKind  `json:"kind"`
	Value     string    `json:"value"`
	Note      string    `json:"note,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// APIKey is a hashed API key.
type APIKey struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"org_id,omitempty"`
	Name       string     `json:"name"`
	Role       string     `json:"role"` // user | analyst | admin
	KeyHash    string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// SubmissionFilter narrows ListSubmissions.
type SubmissionFilter struct {
	OrgID   string
	Verdict domain.Verdict
	Status  domain.Status
	Since   time.Time
	Limit   int
	Offset  int
}

// Stats is the /v1/stats payload (F-4.7.1, F-4.8.1).
type Stats struct {
	Since        time.Time      `json:"since"`
	Total        int            `json:"total"`
	ByVerdict    map[string]int `json:"by_verdict"`
	ByStatus     map[string]int `json:"by_status"`
	ByAttackType map[string]int `json:"by_attack_type"`
	TopBrands    []NameCount    `json:"top_brands"`
	TopSignals   []NameCount    `json:"top_signals"`
	AvgDuration  int            `json:"avg_duration_ms"`
}

// NameCount is a ranked pair.
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// AuditEntry records a privileged action.
type AuditEntry struct {
	OrgID   string
	Actor   string
	Action  string
	Target  string
	Details string
}

// Store is the persistence contract.
type Store interface {
	Migrate(ctx context.Context) error
	SaveSubmission(ctx context.Context, sub *domain.Submission, storeBodies bool) error
	GetSubmission(ctx context.Context, id string) (*domain.Submission, error)
	ListSubmissions(ctx context.Context, f SubmissionFilter) ([]*domain.Submission, error)
	UpdateSubmissionStatus(ctx context.Context, id string, status domain.Status, reviewedBy string) error
	DeleteSubmission(ctx context.Context, id string) error
	PurgeOlderThan(ctx context.Context, cutoff time.Time) (int64, error)

	ListEntries(ctx context.Context, orgID string, kind ListKind) ([]ListEntry, error)
	AddEntry(ctx context.Context, e ListEntry) error
	RemoveEntry(ctx context.Context, orgID string, kind ListKind, value string) error

	ListBrands(ctx context.Context, orgID string) ([]brands.Brand, error)
	AddBrand(ctx context.Context, b brands.Brand) error

	CreateAPIKey(ctx context.Context, k APIKey) error
	GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error)
	ListAPIKeys(ctx context.Context, orgID string) ([]APIKey, error)
	RevokeAPIKey(ctx context.Context, id string) error

	Stats(ctx context.Context, orgID string, since time.Time) (*Stats, error)
	Audit(ctx context.Context, e AuditEntry) error
	Close() error
}

// Open returns the configured backend.
func Open(cfg config.Storage) (Store, error) {
	switch cfg.Driver {
	case "sqlite":
		return openSQLite(cfg.DSN)
	case "postgres":
		// TODO: pgx + golang-migrate postgres driver; same SQL apart from AUTOINCREMENT → GENERATED.
		return nil, fmt.Errorf("%w: postgres driver", ErrNotImplemented)
	default:
		return nil, fmt.Errorf("store: unknown driver %q", cfg.Driver)
	}
}
