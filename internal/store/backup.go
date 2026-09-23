package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BackupSQLite creates a consistent SQLite snapshot without copying a live
// WAL file. The output is a standalone database suitable for validation and
// restore while the service is stopped.
func BackupSQLite(ctx context.Context, dsn, destination string) error {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(dsn)), "postgres") {
		return errors.New("store: SQLite backup cannot be used with PostgreSQL")
	}
	if strings.TrimSpace(destination) == "" {
		return errors.New("store: backup destination is required")
	}
	destination, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if _, err := os.Stat(destination); err == nil {
		return fmt.Errorf("store: backup destination already exists: %s", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return err
	}
	s, err := openSQLite(dsn)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, destination); err != nil {
		return fmt.Errorf("store: SQLite backup: %w", err)
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return err
	}
	return validateSQLiteFile(ctx, destination)
}

// RestoreSQLite validates a snapshot and atomically replaces the configured
// SQLite file. The caller must stop the running service first.
func RestoreSQLite(ctx context.Context, dsn, source string, force bool) error {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(dsn)), "postgres") {
		return errors.New("store: SQLite restore cannot be used with PostgreSQL")
	}
	target := sqlitePath(dsn)
	if target == "" || target == ":memory:" {
		return errors.New("store: restore requires a file-backed SQLite DSN")
	}
	source, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return err
	}
	if same, _ := filepath.Abs(source); same == target {
		return errors.New("store: restore source and destination must differ")
	}
	if err := validateSQLiteFile(ctx, source); err != nil {
		return fmt.Errorf("store: invalid backup: %w", err)
	}
	if _, err := os.Stat(target); err == nil && !force {
		return fmt.Errorf("store: restore destination exists; use --force: %s", target)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	tmp := target + ".restore.tmp"
	_ = os.Remove(tmp)
	if err := copyFile(source, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("store: replace SQLite database: %w", err)
	}
	return nil
}

func validateSQLiteFile(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	var result string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("integrity_check: %s", result)
	}
	return nil
}

func copyFile(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := in.Stat(); err != nil {
		_ = out.Close()
		return err
	}
	if _, err := out.ReadFrom(in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
