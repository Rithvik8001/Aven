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
//
// refresh_tokens stores its timestamps as Unix seconds rather than the RFC 3339
// text used for users.created_at, because every one of them is compared against
// "now" in a WHERE clause. RFC3339Nano is not fixed-width — a whole second
// serialises without a fractional part — so lexical ordering does not match
// chronological ordering, and a range query over it would be quietly wrong.
// users.created_at is only ever read back, never compared, so text is fine
// there.
//
// The hash is a BLOB: storing raw SHA-256 bytes as TEXT would fail STRICT's
// type check, and encoding them first would only add a step to every lookup.
// ON DELETE CASCADE means removing a user takes their sessions with them, which
// works because the DSN turns foreign keys on.
const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            TEXT NOT NULL PRIMARY KEY,
    email         TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (lower(email));

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         TEXT NOT NULL PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    family_id  TEXT NOT NULL,
    token_hash BLOB NOT NULL,
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    revoked_at INTEGER
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS refresh_tokens_hash_unique ON refresh_tokens (token_hash);
CREATE INDEX IF NOT EXISTS refresh_tokens_family ON refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_user ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_expires_at ON refresh_tokens (expires_at);
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
