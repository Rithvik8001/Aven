// Package database opens and configures the SQLite connection.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	// Registers the pure-Go SQLite driver with database/sql under the name
	// "sqlite". Imported only for that side effect, hence the blank import.
	_ "modernc.org/sqlite"
)

// Open connects to the SQLite file at path and verifies it is reachable.
//
// The PRAGMAs go in the connection string rather than being executed after
// connecting, because database/sql keeps a pool: a PRAGMA run once would apply
// to a single connection and silently miss the rest.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	// WAL lets readers run while a write is in progress; busy_timeout waits
	// for a lock instead of failing instantly; foreign_keys is off by
	// default in SQLite and has to be asked for.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// SQLite allows one writer at a time, so a large pool adds contention
	// rather than throughput.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	// sql.Open is lazy and never touches the file, so ping to find out now
	// whether the database is actually usable.
	if err := db.PingContext(ctx); err != nil {
		db.Close()

		return nil, fmt.Errorf("connect to database: %w", err)
	}

	return db, nil
}
