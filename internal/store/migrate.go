package store

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phishlens/phishlens/migrations"
)

// applyMigrations runs embedded NNNN_name.up.sql files newer than the recorded
// version inside transactions. Compatible with golang-migrate file naming so the
// tool can replace this runner later.
func applyMigrations(ctx context.Context, db *sql.DB, postgres bool) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("migrate: init: %w", err)
	}
	var current int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("migrate: read version: %w", err)
	}
	files, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, name := range files {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}
		if version <= current {
			continue
		}
		body, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return err
		}
		if postgres {
			body = postgresMigration(body)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate: %s: %w", name, err)
		}
		migrationInsert := `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`
		if postgres {
			migrationInsert = `INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)`
		}
		if _, err := tx.ExecContext(ctx, migrationInsert, version, time.Now().UTC().Format(time.RFC3339)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// postgresMigration converts the intentionally portable schema into the two
// PostgreSQL-specific DDL forms used by the embedded migrations. Runtime
// queries stay portable and use the SQLStore placeholder adapter.
func postgresMigration(body []byte) []byte {
	s := string(body)
	s = strings.ReplaceAll(s, "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
	return []byte(s)
}

// MigrationVersion returns the current schema version.
func MigrationVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v int
	err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}

// migrateDown reverts the latest migration using its .down.sql.
func migrateDown(ctx context.Context, db *sql.DB, postgres bool) error {
	current, err := MigrationVersion(ctx, db)
	if err != nil || current == 0 {
		return err
	}
	files, _ := fs.Glob(migrations.FS, fmt.Sprintf("%04d_*.down.sql", current))
	if len(files) == 0 {
		return fmt.Errorf("migrate: no down file for version %d", current)
	}
	body, err := fs.ReadFile(migrations.FS, files[0])
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(body)); err != nil {
		_ = tx.Rollback()
		return err
	}
	deleteMigration := `DELETE FROM schema_migrations WHERE version = ?`
	if postgres {
		deleteMigration = `DELETE FROM schema_migrations WHERE version = $1`
	}
	if _, err := tx.ExecContext(ctx, deleteMigration, current); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func migrationVersion(name string) (int, error) {
	i := strings.Index(name, "_")
	if i <= 0 {
		return 0, fmt.Errorf("migrate: bad file name %q", name)
	}
	return strconv.Atoi(name[:i])
}
