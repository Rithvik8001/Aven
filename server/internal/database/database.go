// Package database opens the SQLite connection and applies the schema.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	// Registers the pure-Go SQLite driver under the name "sqlite". Imported
	// only for that side effect.
	_ "modernc.org/sqlite"
)

// schema is applied on every startup. CREATE TABLE IF NOT EXISTS makes that
// idempotent; a real migration runner arrives when the schema first needs to
// change.
//
// STRICT rejects a value of the wrong type instead of silently storing it.
// The email index is on lower(email) so Ada@example.com and ada@example.com
// cannot both register.
const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            TEXT NOT NULL PRIMARY KEY,
    email         TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (lower(email));
`

// Open connects to SQLite, applies the schema, and verifies the database is
// reachable. It fails fast: a service that cannot reach its database should
// refuse to start rather than serve errors.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	// PRAGMAs go in the DSN, not in a statement after connecting:
	// database/sql pools connections, so a PRAGMA executed once would apply
	// to one connection and silently miss the rest.
	//
	// WAL lets readers run during a write; busy_timeout waits for a lock
	// instead of failing instantly; foreign_keys is off by default in SQLite.
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)",
		path,
	)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// SQLite allows one writer at a time, so a large pool adds lock
	// contention rather than throughput.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	// sql.Open is lazy and never touches the file, so ping to find out now
	// whether the database is usable.
	if err := db.PingContext(ctx); err != nil {
		db.Close()

		return nil, fmt.Errorf("connect to database: %w", err)
	}

	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()

		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return db, nil
}
