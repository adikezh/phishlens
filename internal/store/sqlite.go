package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/phishlens/phishlens/internal/brands"
	"github.com/phishlens/phishlens/internal/crypto"
	"github.com/phishlens/phishlens/internal/domain"
)

// SQLite is the modernc.org/sqlite implementation.
type SQLite struct {
	db       *sql.DB
	postgres bool
	cipher   crypto.Cipher // nil → bodies stored as plaintext JSON (only when store_bodies=true)
}

func openSQLite(dsn string) (*SQLite, error) {
	if p := sqlitePath(dsn); p != "" && p != ":memory:" {
		_ = os.MkdirAll(filepath.Dir(p), 0o750)
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL + single writer keeps modernc happy under load
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("store: ping sqlite: %w", err)
	}
	return &SQLite{db: db}, nil
}

// sqlitePath extracts the file path from "file:path?opts".
func sqlitePath(dsn string) string {
	p := strings.TrimPrefix(dsn, "file:")
	if i := strings.Index(p, "?"); i >= 0 {
		p = p[:i]
	}
	return p
}

// SetCipher enables encryption of stored bodies.
func (s *SQLite) SetCipher(c crypto.Cipher) { s.cipher = c }

// DB exposes the handle (migrations CLI).
func (s *SQLite) DB() *sql.DB { return s.db }

// Migrate applies embedded migrations.
func (s *SQLite) Migrate(ctx context.Context) error { return applyMigrations(ctx, s.db, s.postgres) }

// MigrateDown reverts the latest migration.
func (s *SQLite) MigrateDown(ctx context.Context) error { return migrateDown(ctx, s.db, s.postgres) }

// Close closes the database.
func (s *SQLite) Close() error { return s.db.Close() }

// sql rewrites the portable '?' placeholder syntax for PostgreSQL. SQLite and
// PostgreSQL share the same Store contract; keeping the query text portable
// makes migrations and behavioral tests easier to compare.
func (s *SQLite) sql(query string) string {
	if !s.postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *SQLite) execContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.sql(query), args...)
}

func (s *SQLite) queryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, s.sql(query), args...)
}

func (s *SQLite) queryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, s.sql(query), args...)
}

// GetReputationCache returns a non-expired provider response.
func (s *SQLite) GetReputationCache(ctx context.Context, key string) (*ReputationCacheEntry, error) {
	var value, expires string
	if err := s.queryRowContext(ctx, `SELECT value, expires_at FROM reputation_cache WHERE key = ?`, key).Scan(&value, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return nil, fmt.Errorf("store: reputation cache expiry: %w", err)
	}
	if !time.Now().Before(expiresAt) {
		_, _ = s.execContext(ctx, `DELETE FROM reputation_cache WHERE key = ?`, key)
		return nil, ErrNotFound
	}
	return &ReputationCacheEntry{Key: key, Value: value, ExpiresAt: expiresAt}, nil
}

// PutReputationCache upserts a bounded provider response.
func (s *SQLite) PutReputationCache(ctx context.Context, key, value string, expiresAt time.Time) error {
	if key == "" || value == "" || expiresAt.IsZero() {
		return fmt.Errorf("store: invalid reputation cache entry")
	}
	_, err := s.execContext(ctx, `INSERT INTO reputation_cache(key, value, expires_at) VALUES(?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, expires_at=excluded.expires_at`, key, value, expiresAt.UTC().Format(time.RFC3339Nano))
	return err
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func toJSON(v any) sql.NullString {
	if v == nil {
		return sql.NullString{}
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" { // typed nil pointers marshal to "null"
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

// SaveSubmission writes submission + analysis + signals in one transaction.
// With storeBodies=false only metadata, signals and score are kept (Community privacy).
func (s *SQLite) SaveSubmission(ctx context.Context, sub *domain.Submission, storeBodies bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var subject, message sql.NullString
	fromDomain := ""
	if sub.Message != nil {
		fromDomain = sub.Message.From.Domain
		if storeBodies {
			subject = sql.NullString{String: sub.Message.Subject, Valid: true}
			enc, err := s.encodeMessage(sub.Message)
			if err != nil {
				return err
			}
			message = sql.NullString{String: enc, Valid: true}
		}
	}
	now := ts(time.Now())
	_, err = tx.ExecContext(ctx, s.sql(`INSERT INTO submissions
		(id, org_id, channel, submitted_by, department, kind, received_at, status, reviewed_by, reviewed_at, from_domain, subject, message_json, campaign_key, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET status=excluded.status, reviewed_by=excluded.reviewed_by, department=excluded.department`),
		sub.ID, sub.OrgID, string(sub.Channel), sub.SubmittedBy, sub.Department, string(sub.Kind), ts(sub.ReceivedAt),
		string(sub.Status), sub.ReviewedBy, nullableTS(sub.ReviewedAt), fromDomain, subject, message, campaignKey(sub), now)
	if err != nil {
		return fmt.Errorf("store: insert submission: %w", err)
	}
	if _, err = tx.ExecContext(ctx, s.sql(`DELETE FROM submission_iocs WHERE submission_id = ?`), sub.ID); err != nil {
		return err
	}
	for _, ioc := range submissionIOCs(sub) {
		if _, err = tx.ExecContext(ctx, s.sql(`INSERT INTO submission_iocs
			(submission_id, org_id, kind, value, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`),
			sub.ID, sub.OrgID, ioc.Kind, ioc.Value, now); err != nil {
			return fmt.Errorf("store: insert ioc: %w", err)
		}
	}
	if a := sub.Result; a != nil {
		_, err = tx.ExecContext(ctx, s.sql(`INSERT INTO analyses
			(submission_id, score, verdict, confidence, attack_type, brand_json, llm_json, recommendations_json, warnings_json, duration_ms)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (submission_id) DO UPDATE SET
			 score = excluded.score, verdict = excluded.verdict, confidence = excluded.confidence,
			 attack_type = excluded.attack_type, brand_json = excluded.brand_json, llm_json = excluded.llm_json,
			 recommendations_json = excluded.recommendations_json, warnings_json = excluded.warnings_json,
			 duration_ms = excluded.duration_ms`),
			sub.ID, a.Score, string(a.Verdict), a.Confidence, string(a.AttackType),
			toJSON(a.Brand), toJSON(a.LLM), toJSON(a.Recommendations), toJSON(a.Warnings), a.DurationMs)
		if err != nil {
			return fmt.Errorf("store: insert analysis: %w", err)
		}
		if _, err = tx.ExecContext(ctx, s.sql(`DELETE FROM signals WHERE submission_id = ?`), sub.ID); err != nil {
			return err
		}
		for _, sg := range a.Signals {
			evidence := sg.Evidence
			if !storeBodies {
				evidence = "" // Community: no fragments of the message are persisted
			}
			if _, err = tx.ExecContext(ctx, s.sql(`INSERT INTO signals
				(submission_id, signal_id, category, weight, confidence, evidence, explanation, source)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
				sub.ID, sg.ID, string(sg.Category), sg.Weight, sg.Confidence, evidence, sg.Explanation, string(sg.Source)); err != nil {
				return fmt.Errorf("store: insert signal: %w", err)
			}
		}
	}
	return tx.Commit()
}

func nullableTS(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return ts(t)
}

func (s *SQLite) encodeMessage(m *domain.ParsedMail) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	if s.cipher == nil {
		return string(b), nil
	}
	sealed, err := s.cipher.Seal(b)
	if err != nil {
		return "", err
	}
	return "enc:" + base64.StdEncoding.EncodeToString(sealed), nil
}

func (s *SQLite) decodeMessage(enc string) (*domain.ParsedMail, error) {
	raw := []byte(enc)
	if strings.HasPrefix(enc, "enc:") {
		if s.cipher == nil {
			return nil, errors.New("store: message is encrypted but no key configured")
		}
		sealed, err := base64.StdEncoding.DecodeString(enc[4:])
		if err != nil {
			return nil, err
		}
		if raw, err = s.cipher.Open(sealed); err != nil {
			return nil, err
		}
	}
	var m domain.ParsedMail
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// campaignKey groups submissions by sender domain + link domains (F-4.6.1).
func campaignKey(sub *domain.Submission) string {
	if sub.Message == nil {
		return ""
	}
	parts := append([]string{sub.Message.From.Domain}, sub.Message.LinkDomains()...)
	return strings.Join(parts, "|")
}

func submissionIOCs(sub *domain.Submission) []IOC {
	if sub == nil || sub.Message == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []IOC
	add := func(kind, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := kind + "\x00" + strings.ToLower(value)
		if seen[key] {
			return
		}
		seen[key] = true
		if kind != "url" {
			value = strings.ToLower(value)
		}
		out = append(out, IOC{OrgID: sub.OrgID, SubmissionID: sub.ID, Kind: kind, Value: value, CreatedAt: sub.ReceivedAt})
	}
	for _, d := range []string{sub.Message.From.Domain, sub.Message.ReplyTo.Domain, sub.Message.ReturnPath.Domain} {
		add("domain", d)
	}
	for _, l := range sub.Message.Links {
		add("domain", l.Domain)
		add("url", l.Href)
	}
	for _, a := range sub.Message.Attachments {
		add("sha256", a.SHA256)
	}
	return out
}

// ListIOCs returns indicators from confirmed phishing submissions only.
func (s *SQLite) ListIOCs(ctx context.Context, orgID string, since time.Time) ([]IOC, error) {
	rows, err := s.queryContext(ctx, `SELECT i.org_id, i.submission_id, i.kind, i.value, i.created_at
		FROM submission_iocs i JOIN submissions s ON s.id = i.submission_id
		WHERE s.status = ? AND s.received_at >= ? AND (s.org_id = ? OR ? = '')
		ORDER BY i.created_at ASC, i.kind, i.value`, string(domain.StatusConfirmedPhish), ts(since), orgID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IOC
	for rows.Next() {
		var i IOC
		var created string
		if err := rows.Scan(&i.OrgID, &i.SubmissionID, &i.Kind, &i.Value, &created); err != nil {
			return nil, err
		}
		i.CreatedAt = parseTS(created)
		out = append(out, i)
	}
	return out, rows.Err()
}

const selectSubmission = `SELECT s.id, s.org_id, s.channel, s.submitted_by, s.department, s.kind, s.received_at, s.status, s.reviewed_by, s.reviewed_at,
	s.subject, s.message_json,
	a.score, a.verdict, a.confidence, a.attack_type, a.brand_json, a.llm_json, a.recommendations_json, a.warnings_json, a.duration_ms
	FROM submissions s LEFT JOIN analyses a ON a.submission_id = s.id`

func (s *SQLite) scanSubmission(ctx context.Context, row interface{ Scan(...any) error }) (*domain.Submission, error) {
	var (
		sub                                  domain.Submission
		received, subject, message           sql.NullString
		score, duration                      sql.NullInt64
		verdict, attack, brand, llm, rec, wr sql.NullString
		conf                                 sql.NullFloat64
		channel, department, kind, status    string
		reviewedAt                           sql.NullString
	)
	if err := row.Scan(&sub.ID, &sub.OrgID, &channel, &sub.SubmittedBy, &department, &kind, &received, &status, &sub.ReviewedBy, &reviewedAt,
		&subject, &message, &score, &verdict, &conf, &attack, &brand, &llm, &rec, &wr, &duration); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	sub.Channel, sub.Kind, sub.Status, sub.Department = domain.Channel(channel), domain.Kind(kind), domain.Status(status), department
	sub.ReceivedAt = parseTS(received.String)
	if reviewedAt.Valid {
		sub.ReviewedAt = parseTS(reviewedAt.String)
	}
	if message.Valid {
		if m, err := s.decodeMessage(message.String); err == nil {
			sub.Message = m
		}
	} else if subject.Valid {
		sub.Message = &domain.ParsedMail{Subject: subject.String}
	}
	if verdict.Valid {
		a := &domain.Analysis{Score: int(score.Int64), Verdict: domain.Verdict(verdict.String), Confidence: conf.Float64,
			AttackType: domain.AttackType(attack.String), DurationMs: int(duration.Int64)}
		if brand.Valid {
			_ = json.Unmarshal([]byte(brand.String), &a.Brand)
		}
		if llm.Valid {
			_ = json.Unmarshal([]byte(llm.String), &a.LLM)
		}
		if rec.Valid {
			_ = json.Unmarshal([]byte(rec.String), &a.Recommendations)
		}
		if wr.Valid {
			_ = json.Unmarshal([]byte(wr.String), &a.Warnings)
		}
		rows, err := s.queryContext(ctx, `SELECT signal_id, category, weight, confidence, evidence, explanation, source FROM signals WHERE submission_id = ? ORDER BY ABS(weight*confidence) DESC`, sub.ID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var sg domain.Signal
			var cat, src string
			if err := rows.Scan(&sg.ID, &cat, &sg.Weight, &sg.Confidence, &sg.Evidence, &sg.Explanation, &src); err != nil {
				return nil, err
			}
			sg.Category, sg.Source = domain.Category(cat), domain.Source(src)
			a.Signals = append(a.Signals, sg)
		}
		sub.Result = a
	}
	return &sub, nil
}

// GetSubmission loads one submission with its analysis and signals.
func (s *SQLite) GetSubmission(ctx context.Context, id string) (*domain.Submission, error) {
	return s.scanSubmission(ctx, s.queryRowContext(ctx, selectSubmission+` WHERE s.id = ?`, id))
}

// ListSubmissions returns newest first.
func (s *SQLite) ListSubmissions(ctx context.Context, f SubmissionFilter) ([]*domain.Submission, error) {
	q := `SELECT s.id FROM submissions s LEFT JOIN analyses a ON a.submission_id = s.id WHERE 1=1`
	var args []any
	if f.OrgID != "" {
		q += ` AND s.org_id = ?`
		args = append(args, f.OrgID)
	}
	if f.SubmittedBy != "" {
		q += ` AND lower(s.submitted_by) = lower(?)`
		args = append(args, f.SubmittedBy)
	}
	if f.Verdict != "" {
		q += ` AND a.verdict = ?`
		args = append(args, string(f.Verdict))
	}
	if f.Status != "" {
		q += ` AND s.status = ?`
		args = append(args, string(f.Status))
	}
	if f.Department != "" {
		q += ` AND s.department = ?`
		args = append(args, f.Department)
	}
	if !f.Since.IsZero() {
		q += ` AND s.received_at >= ?`
		args = append(args, ts(f.Since))
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q += ` ORDER BY s.received_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, f.Offset)
	rows, err := s.queryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	out := make([]*domain.Submission, 0, len(ids))
	for _, id := range ids {
		sub, err := s.GetSubmission(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, nil
}

// UpdateSubmissionStatus changes review status (F-4.6.2).
func (s *SQLite) UpdateSubmissionStatus(ctx context.Context, id string, status domain.Status, reviewedBy string) error {
	var reviewedAt any
	if status == domain.StatusConfirmedPhish || status == domain.StatusConfirmedClean || status == domain.StatusEscalated {
		reviewedAt = ts(time.Now())
	}
	res, err := s.execContext(ctx, `UPDATE submissions SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?`, string(status), reviewedBy, reviewedAt, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSubmission removes a submission and its children (privacy: DELETE /v1/submissions/{id}).
func (s *SQLite) DeleteSubmission(ctx context.Context, id string) error {
	for _, q := range []string{`DELETE FROM signals WHERE submission_id = ?`, `DELETE FROM analyses WHERE submission_id = ?`} {
		if _, err := s.execContext(ctx, q, id); err != nil {
			return err
		}
	}
	res, err := s.execContext(ctx, `DELETE FROM submissions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeOlderThan enforces retention.
func (s *SQLite) PurgeOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	c := ts(cutoff)
	if _, err := s.execContext(ctx, `DELETE FROM submission_iocs WHERE submission_id IN (SELECT id FROM submissions WHERE received_at < ?)`, c); err != nil {
		return 0, err
	}
	if _, err := s.execContext(ctx, `DELETE FROM signals WHERE submission_id IN (SELECT id FROM submissions WHERE received_at < ?)`, c); err != nil {
		return 0, err
	}
	if _, err := s.execContext(ctx, `DELETE FROM analyses WHERE submission_id IN (SELECT id FROM submissions WHERE received_at < ?)`, c); err != nil {
		return 0, err
	}
	res, err := s.execContext(ctx, `DELETE FROM submissions WHERE received_at < ?`, c)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func listTable(kind ListKind) string {
	if kind == ListBlock {
		return "blocklist"
	}
	return "allowlist"
}

// ListEntries returns entries for an org (” = global).
func (s *SQLite) ListEntries(ctx context.Context, orgID string, kind ListKind) ([]ListEntry, error) {
	rows, err := s.queryContext(ctx, `SELECT org_id, value, note, created_by, created_at FROM `+listTable(kind)+` WHERE org_id = ? OR org_id = '' ORDER BY value`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ListEntry
	for rows.Next() {
		var e ListEntry
		var created string
		if err := rows.Scan(&e.OrgID, &e.Value, &e.Note, &e.CreatedBy, &created); err != nil {
			return nil, err
		}
		e.Kind, e.CreatedAt = kind, parseTS(created)
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddEntry inserts or ignores a list entry.
func (s *SQLite) AddEntry(ctx context.Context, e ListEntry) error {
	_, err := s.execContext(ctx, `INSERT INTO `+listTable(e.Kind)+` (org_id, value, note, created_by, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
		e.OrgID, strings.ToLower(strings.TrimSpace(e.Value)), e.Note, e.CreatedBy, ts(time.Now()))
	return err
}

// RemoveEntry deletes a list entry.
func (s *SQLite) RemoveEntry(ctx context.Context, orgID string, kind ListKind, value string) error {
	res, err := s.execContext(ctx, `DELETE FROM `+listTable(kind)+` WHERE org_id = ? AND value = ?`, orgID, strings.ToLower(value))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListBrands returns custom brands for an org (F-4.3.4).
func (s *SQLite) ListBrands(ctx context.Context, orgID string) ([]brands.Brand, error) {
	rows, err := s.queryContext(ctx, `SELECT org_id, name, domains, esp_domains, keywords, locale, colors, logo_phash FROM brands WHERE org_id = ? OR org_id = '' ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []brands.Brand
	for rows.Next() {
		var b brands.Brand
		var d, e, k, colors string
		if err := rows.Scan(&b.OrgID, &b.Name, &d, &e, &k, &b.Locale, &colors, &b.LogoPHash); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(d), &b.Domains)
		_ = json.Unmarshal([]byte(e), &b.ESPDomains)
		_ = json.Unmarshal([]byte(k), &b.Keywords)
		_ = json.Unmarshal([]byte(colors), &b.Colors)
		out = append(out, b)
	}
	return out, rows.Err()
}

// AddBrand upserts a custom brand.
func (s *SQLite) AddBrand(ctx context.Context, b brands.Brand) error {
	d, _ := json.Marshal(b.Domains)
	e, _ := json.Marshal(b.ESPDomains)
	k, _ := json.Marshal(b.Keywords)
	colors, _ := json.Marshal(b.Colors)
	_, err := s.execContext(ctx, `INSERT INTO brands (org_id, name, domains, esp_domains, keywords, locale, colors, logo_phash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(org_id, name) DO UPDATE SET domains=excluded.domains, esp_domains=excluded.esp_domains, keywords=excluded.keywords, locale=excluded.locale, colors=excluded.colors, logo_phash=excluded.logo_phash`,
		b.OrgID, b.Name, string(d), string(e), string(k), b.Locale, string(colors), b.LogoPHash, ts(time.Now()))
	return err
}

// CreateAPIKey stores a hashed key.
func (s *SQLite) CreateAPIKey(ctx context.Context, k APIKey) error {
	_, err := s.execContext(ctx, `INSERT INTO api_keys (id, org_id, name, role, key_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		k.ID, k.OrgID, k.Name, k.Role, k.KeyHash, ts(k.CreatedAt))
	return err
}

// GetAPIKeyByHash looks up an active key and touches last_used_at.
func (s *SQLite) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error) {
	var k APIKey
	var created string
	var lastUsed, revoked sql.NullString
	err := s.queryRowContext(ctx, `SELECT id, org_id, name, role, key_hash, created_at, last_used_at, revoked_at FROM api_keys WHERE key_hash = ?`, hash).
		Scan(&k.ID, &k.OrgID, &k.Name, &k.Role, &k.KeyHash, &created, &lastUsed, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	k.CreatedAt = parseTS(created)
	if revoked.Valid {
		t := parseTS(revoked.String)
		k.RevokedAt = &t
	}
	if lastUsed.Valid {
		t := parseTS(lastUsed.String)
		k.LastUsedAt = &t
	}
	_, _ = s.execContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, ts(time.Now()), k.ID)
	return &k, nil
}

// ListAPIKeys lists keys for an org.
func (s *SQLite) ListAPIKeys(ctx context.Context, orgID string) ([]APIKey, error) {
	rows, err := s.queryContext(ctx, `SELECT id, org_id, name, role, created_at, last_used_at, revoked_at FROM api_keys WHERE org_id = ? OR ? = '' ORDER BY created_at DESC`, orgID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		var created string
		var lastUsed, revoked sql.NullString
		if err := rows.Scan(&k.ID, &k.OrgID, &k.Name, &k.Role, &created, &lastUsed, &revoked); err != nil {
			return nil, err
		}
		k.CreatedAt = parseTS(created)
		if lastUsed.Valid {
			t := parseTS(lastUsed.String)
			k.LastUsedAt = &t
		}
		if revoked.Valid {
			t := parseTS(revoked.String)
			k.RevokedAt = &t
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeAPIKey marks a key revoked.
func (s *SQLite) RevokeAPIKey(ctx context.Context, id string) error {
	res, err := s.execContext(ctx, `UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, ts(time.Now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) sealWebhookSecret(secret string) (string, error) {
	if s.cipher == nil {
		return "", errors.New("store: webhook secret requires storage encryption key")
	}
	sealed, err := s.cipher.Seal([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("store: encrypt webhook secret: %w", err)
	}
	return "enc:" + base64.StdEncoding.EncodeToString(sealed), nil
}

func (s *SQLite) openWebhookSecret(ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, "enc:") || s.cipher == nil {
		return "", errors.New("store: webhook secret is unavailable without storage encryption key")
	}
	b, err := base64.StdEncoding.DecodeString(ciphertext[4:])
	if err != nil {
		return "", fmt.Errorf("store: decode webhook secret: %w", err)
	}
	plain, err := s.cipher.Open(b)
	if err != nil {
		return "", fmt.Errorf("store: decrypt webhook secret: %w", err)
	}
	return string(plain), nil
}

// ListWebhooks returns subscriptions visible to an organization. Empty orgID
// is reserved for administrative/global inspection.
func (s *SQLite) ListWebhooks(ctx context.Context, orgID string) ([]Webhook, error) {
	rows, err := s.queryContext(ctx, `SELECT id, org_id, name, url, secret_cipher, enabled, created_at
		FROM webhooks WHERE org_id = ? OR ? = '' ORDER BY created_at DESC`, orgID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		var w Webhook
		var secretCipher, created string
		var enabled int
		if err := rows.Scan(&w.ID, &w.OrgID, &w.Name, &w.URL, &secretCipher, &enabled, &created); err != nil {
			return nil, err
		}
		w.Enabled, w.CreatedAt = enabled != 0, parseTS(created)
		w.Secret, err = s.openWebhookSecret(secretCipher)
		if err != nil {
			return nil, err
		}
		w.SecretConfigured = w.Secret != ""
		out = append(out, w)
	}
	return out, rows.Err()
}

// CreateWebhook persists an encrypted HMAC secret.
func (s *SQLite) CreateWebhook(ctx context.Context, w Webhook) error {
	secret, err := s.sealWebhookSecret(w.Secret)
	if err != nil {
		return err
	}
	enabled := 0
	if w.Enabled {
		enabled = 1
	}
	_, err = s.execContext(ctx, `INSERT INTO webhooks
		(id, org_id, name, url, secret_cipher, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET name=excluded.name, url=excluded.url,
		secret_cipher=excluded.secret_cipher, enabled=excluded.enabled`,
		w.ID, w.OrgID, w.Name, w.URL, secret, enabled, ts(w.CreatedAt))
	return err
}

// DeleteWebhook removes one subscription within the caller's organization.
func (s *SQLite) DeleteWebhook(ctx context.Context, orgID, id string) error {
	res, err := s.execContext(ctx, `DELETE FROM webhooks WHERE org_id = ? AND id = ?`, orgID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Stats aggregates counts since a point in time.
func (s *SQLite) Stats(ctx context.Context, orgID string, since time.Time) (*Stats, error) {
	st := &Stats{Since: since, ByVerdict: map[string]int{}, ByStatus: map[string]int{}, ByAttackType: map[string]int{}, ByDepartment: map[string]int{}}
	where := ` WHERE s.received_at >= ? AND (s.org_id = ? OR ? = '')`
	args := []any{ts(since), orgID, orgID}
	group := func(q string, into map[string]int) error {
		rows, err := s.queryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k sql.NullString
			var n int
			if err := rows.Scan(&k, &n); err != nil {
				return err
			}
			into[k.String] = n
		}
		return rows.Err()
	}
	if err := group(`SELECT a.verdict, COUNT(*) FROM submissions s JOIN analyses a ON a.submission_id = s.id`+where+` GROUP BY a.verdict`, st.ByVerdict); err != nil {
		return nil, err
	}
	if err := group(`SELECT s.status, COUNT(*) FROM submissions s`+where+` GROUP BY s.status`, st.ByStatus); err != nil {
		return nil, err
	}
	if err := group(`SELECT a.attack_type, COUNT(*) FROM submissions s JOIN analyses a ON a.submission_id = s.id`+where+` GROUP BY a.attack_type`, st.ByAttackType); err != nil {
		return nil, err
	}
	if err := group(`SELECT s.department, COUNT(*) FROM submissions s`+where+` AND s.department <> '' GROUP BY s.department`, st.ByDepartment); err != nil {
		return nil, err
	}
	for _, n := range st.ByStatus {
		st.Total += n
	}
	var avg sql.NullFloat64
	if err := s.queryRowContext(ctx, `SELECT AVG(a.duration_ms) FROM submissions s JOIN analyses a ON a.submission_id = s.id`+where, args...).Scan(&avg); err == nil {
		st.AvgDuration = int(avg.Float64)
	}
	rows, err := s.queryContext(ctx, `SELECT s.received_at, s.reviewed_at FROM submissions s`+where+` AND s.reviewed_at IS NOT NULL`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var totalReview time.Duration
	var reviewCount int
	for rows.Next() {
		var received, reviewed string
		if err := rows.Scan(&received, &reviewed); err != nil {
			return nil, err
		}
		d := parseTS(reviewed).Sub(parseTS(received))
		if d >= 0 {
			totalReview += d
			reviewCount++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if reviewCount > 0 {
		st.AvgReviewDuration = int((totalReview / time.Duration(reviewCount)) / time.Millisecond)
	}
	top := func(q string) ([]NameCount, error) {
		rows, err := s.queryContext(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []NameCount
		for rows.Next() {
			var name sql.NullString
			var nc NameCount
			if err := rows.Scan(&name, &nc.Count); err != nil {
				return nil, err
			}
			if !name.Valid || name.String == "" {
				continue
			}
			nc.Name = name.String
			out = append(out, nc)
		}
		return out, rows.Err()
	}
	if st.TopSignals, err = top(`SELECT g.signal_id, COUNT(*) c FROM signals g JOIN submissions s ON s.id = g.submission_id` + where + ` GROUP BY g.signal_id ORDER BY c DESC LIMIT 10`); err != nil {
		return nil, err
	}
	brandName := `json_extract(a.brand_json, '$.name')`
	if s.postgres {
		brandName = `a.brand_json::jsonb ->> 'name'`
	}
	if st.TopBrands, err = top(`SELECT ` + brandName + `, COUNT(*) c FROM submissions s JOIN analyses a ON a.submission_id = s.id` + where + ` AND a.brand_json IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10`); err != nil {
		return nil, err
	}
	return st, nil
}

// Audit appends an audit row.
func (s *SQLite) Audit(ctx context.Context, e AuditEntry) error {
	_, err := s.execContext(ctx, `INSERT INTO audit (org_id, actor, action, target, details, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		e.OrgID, e.Actor, e.Action, e.Target, e.Details, ts(time.Now()))
	return err
}
