package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// openPostgres opens the PostgreSQL implementation through database/sql. The
// shared SQLite type contains the persistence logic and switches only the
// placeholder, upsert, JSON-expression, and migration dialects.
func openPostgres(dsn string) (*SQLite, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres: %w", err)
	}
	// PostgreSQL handles concurrent writers; keep a bounded pool so a single
	// service instance cannot exhaust the database connection budget.
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping postgres: %w", err)
	}
	return &SQLite{db: db, postgres: true}, nil
}
