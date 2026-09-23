// Package store persists submissions, analyses, signals, lists, brands, API keys
// and audit records (ТЗ §3). SQLite via modernc (no cgo) and PostgreSQL via pgx
// implement the same contract. Queries are hand-written; sqlc generation is
// wired in sqlc.yaml for later.
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
	// ErrNotImplemented is retained for callers that used the old driver sentinel.
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

// Webhook is an org-scoped HMAC webhook subscription. Secret is internal
// runtime material and is never serialized by the API because of json:"-".
type Webhook struct {
	ID               string    `json:"id"`
	OrgID            string    `json:"org_id,omitempty"`
	Name             string    `json:"name"`
	URL              string    `json:"url"`
	Enabled          bool      `json:"enabled"`
	Secret           string    `json:"-"`
	SecretConfigured bool      `json:"secret_configured"`
	CreatedAt        time.Time `json:"created_at"`
}

// SubmissionFilter narrows ListSubmissions.
type SubmissionFilter struct {
	OrgID      string
	Verdict    domain.Verdict
	Status     domain.Status
	Department string
	Since      time.Time
	Limit      int
	Offset     int
}

// Stats is the /v1/stats payload (F-4.7.1, F-4.8.1).
type Stats struct {
	Since             time.Time      `json:"since"`
	Total             int            `json:"total"`
	ByVerdict         map[string]int `json:"by_verdict"`
	ByStatus          map[string]int `json:"by_status"`
	ByAttackType      map[string]int `json:"by_attack_type"`
	ByDepartment      map[string]int `json:"by_department"`
	TopBrands         []NameCount    `json:"top_brands"`
	TopSignals        []NameCount    `json:"top_signals"`
	AvgDuration       int            `json:"avg_duration_ms"`
	AvgReviewDuration int            `json:"avg_review_duration_ms"`
}

// NameCount is a ranked pair.
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// IOC is privacy-safe indicator metadata retained independently of message
// bodies, so Community mode can export confirmed indicators without storing
// the submitted email.
type IOC struct {
	OrgID        string    `json:"org_id,omitempty"`
	SubmissionID string    `json:"submission_id"`
	Kind         string    `json:"kind"` // domain | url | sha256
	Value        string    `json:"value"`
	CreatedAt    time.Time `json:"created_at"`
}

// ReputationCacheEntry is a privacy-safe provider response keyed only by a
// normalized indicator key (for example rdap:example.com).
type ReputationCacheEntry struct {
	Key       string
	Value     string
	ExpiresAt time.Time
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
	ListIOCs(ctx context.Context, orgID string, since time.Time) ([]IOC, error)
	GetReputationCache(ctx context.Context, key string) (*ReputationCacheEntry, error)
	PutReputationCache(ctx context.Context, key, value string, expiresAt time.Time) error

	ListEntries(ctx context.Context, orgID string, kind ListKind) ([]ListEntry, error)
	AddEntry(ctx context.Context, e ListEntry) error
	RemoveEntry(ctx context.Context, orgID string, kind ListKind, value string) error

	ListBrands(ctx context.Context, orgID string) ([]brands.Brand, error)
	AddBrand(ctx context.Context, b brands.Brand) error

	CreateAPIKey(ctx context.Context, k APIKey) error
	GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error)
	ListAPIKeys(ctx context.Context, orgID string) ([]APIKey, error)
	RevokeAPIKey(ctx context.Context, id string) error

	ListWebhooks(ctx context.Context, orgID string) ([]Webhook, error)
	CreateWebhook(ctx context.Context, w Webhook) error
	DeleteWebhook(ctx context.Context, orgID, id string) error

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
		return openPostgres(cfg.DSN)
	default:
		return nil, fmt.Errorf("store: unknown driver %q", cfg.Driver)
	}
}
