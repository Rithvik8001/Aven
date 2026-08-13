package user

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// bcryptCost sets the work factor. Each increment doubles the time to hash.
//
// 12 is a deliberate step above bcrypt's default of 10: the cost of a login is a
// few hundred milliseconds of server CPU, while the cost to an attacker running
// a stolen-hash dictionary attack goes up by the same factor. Raise it as
// hardware improves.
const bcryptCost = 12

// Store persists users.
type Store struct {
	db *sql.DB
}

// NewStore builds a Store.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Create hashes the password and inserts a new user.
//
// It returns ErrEmailTaken when the address is already registered, detected from
// the unique index rather than a prior SELECT: checking first would leave a
// window in which two concurrent requests both find the address free.
func (s *Store) Create(ctx context.Context, in SignupInput) (User, error) {
	// bcrypt generates its own salt and embeds it, along with the cost, in
	// the output — so nothing else needs to be stored alongside the hash.
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcryptCost)
	if err != nil {
		return User{}, fmt.Errorf("user: hash password: %w", err)
	}

	newUser := User{
		// UUIDv7 rather than a sequential integer: a counting ID would let
		// anyone enumerate every account, and v7 keeps the time ordering
		// that gives an index good locality.
		ID: mustNewUUIDv7(),
		// Stored as entered so the user sees their own capitalisation; the
		// unique index on lower(email) is what enforces uniqueness.
		Email:        in.Email,
		DisplayName:  in.DisplayName,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		PasswordHash: string(hash),
	}

	const query = `
		INSERT INTO users (id, email, display_name, password_hash, created_at)
		VALUES (?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query,
		newUser.ID, newUser.Email, newUser.DisplayName, newUser.PasswordHash, newUser.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrEmailTaken
		}

		return User{}, fmt.Errorf("user: insert: %w", err)
	}

	return newUser, nil
}

// isUniqueViolation reports whether err is a SQLite UNIQUE constraint failure.
//
// The driver exposes the code only inside the message, so this matches on text.
// It is isolated here as the single place to change if the driver ever grows a
// typed error.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// mustNewUUIDv7 generates a time-ordered UUID.
//
// It panics only if the system's random source fails, which means the process
// cannot generate a safe identifier and should not continue — the panic is
// caught by the recovery middleware and returned as a 500.
func mustNewUUIDv7() string {
	id, err := uuid.NewV7()
	if err != nil {
		panic(fmt.Sprintf("user: generate uuid: %v", err))
	}

	return id.String()
}
