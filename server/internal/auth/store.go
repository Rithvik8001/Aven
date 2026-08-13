package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RefreshToken is a persisted refresh token.
//
// The token itself is never a field here — only its hash. The raw value exists
// for exactly as long as it takes to put it in a Set-Cookie header.
type RefreshToken struct {
	ID       string
	UserID   string
	FamilyID string
	Hash     []byte

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Store persists refresh tokens.
type Store struct {
	db *sql.DB
}

// NewStore builds a Store.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Create records a newly issued refresh token.
func (s *Store) Create(ctx context.Context, token RefreshToken) error {
	if err := insert(ctx, s.db, token); err != nil {
		return fmt.Errorf("auth: insert refresh token: %w", err)
	}

	return nil
}

// Rotate spends the token identified by hash and issues next in its place,
// returning the owner of both.
//
// Rotation is the whole point of storing these rows. A refresh token is usable
// once; presenting it yields a new one and kills the old. That turns a stolen
// token into a token that stops working as soon as the real client refreshes —
// and, more usefully, makes the theft visible.
//
// The spend is a single conditional UPDATE rather than a SELECT followed by an
// UPDATE. Two concurrent requests carrying the same token both pass a SELECT;
// only one can match `used_at IS NULL` in an UPDATE. Doing it in one statement
// is what makes "used exactly once" true rather than merely likely.
//
// A consequence worth knowing: a client that fires two refreshes in parallel
// looks exactly like a thief, and loses its session. Clients must serialise
// refreshes. That is the strict reading, and it is chosen on purpose — a grace
// window for double-submits is also a window in which a stolen token still
// works.
func (s *Store) Rotate(ctx context.Context, hash []byte, next RefreshToken, now time.Time) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("auth: begin rotation: %w", err)
	}

	// Rollback on every path that does not reach Commit. After a successful
	// Commit this is a no-op that returns ErrTxDone.
	defer func() { _ = tx.Rollback() }()

	const spend = `
		UPDATE refresh_tokens
		   SET used_at = ?
		 WHERE token_hash = ?
		   AND used_at IS NULL
		   AND revoked_at IS NULL
		   AND expires_at > ?
	 RETURNING user_id, family_id`

	unix := now.Unix()

	var userID, familyID string

	err = tx.QueryRowContext(ctx, spend, unix, hash, unix).Scan(&userID, &familyID)

	switch {
	case err == nil:
	case errors.Is(err, sql.ErrNoRows):
		// The UPDATE matched nothing. Either the token does not exist,
		// or it exists and was already spent — which are very different
		// events, so find out which before answering.
		return "", s.classifyMiss(ctx, tx, hash, now)
	default:
		return "", fmt.Errorf("auth: spend refresh token: %w", err)
	}

	next.UserID = userID
	next.FamilyID = familyID

	if err := insert(ctx, tx, next); err != nil {
		return "", fmt.Errorf("auth: insert rotated token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("auth: commit rotation: %w", err)
	}

	return userID, nil
}

// classifyMiss decides why the conditional UPDATE matched no row, and revokes
// the family when the answer is reuse.
//
// A token that exists but is already spent means two parties hold it. There is
// no way to tell which of them is the legitimate client, so neither is trusted:
// the entire family — every token rotated from the same login — is revoked, and
// the user has to sign in again. Ending one real session is the correct price
// for shutting down a stolen one.
func (s *Store) classifyMiss(ctx context.Context, tx *sql.Tx, hash []byte, now time.Time) error {
	const lookup = `
		SELECT family_id, used_at IS NOT NULL, revoked_at IS NOT NULL, expires_at
		  FROM refresh_tokens
		 WHERE token_hash = ?`

	var (
		familyID  string
		used      bool
		revoked   bool
		expiresAt int64
	)

	err := tx.QueryRowContext(ctx, lookup, hash).Scan(&familyID, &used, &revoked, &expiresAt)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Never issued, or already cleaned up after expiry. Nothing to
		// revoke and nothing to read into it.
		return ErrInvalidRefreshToken
	case err != nil:
		return fmt.Errorf("auth: inspect refresh token: %w", err)
	}

	// An expired token is an ordinary end-of-session, not an attack —
	// including one that expired after being spent, which is just an old row
	// awaiting cleanup.
	if expiresAt <= now.Unix() {
		return ErrInvalidRefreshToken
	}

	// Already revoked: the family was torn down by an earlier reuse or a
	// logout. Revoking again would add nothing.
	if revoked {
		return ErrInvalidRefreshToken
	}

	if !used {
		// Live, unused, unrevoked, unexpired — yet the UPDATE missed it.
		// No condition remains that could explain this.
		return fmt.Errorf("auth: refresh token %s failed to spend for no known reason", familyID)
	}

	const revokeFamily = `
		UPDATE refresh_tokens
		   SET revoked_at = ?
		 WHERE family_id = ?
		   AND revoked_at IS NULL`

	if _, err := tx.ExecContext(ctx, revokeFamily, now.Unix(), familyID); err != nil {
		return fmt.Errorf("auth: revoke reused family: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("auth: commit family revocation: %w", err)
	}

	return ErrRefreshReuse
}

// RevokeFamilyByToken revokes every token sharing a family with the one hashed
// to hash. This is what logout does: ending the session, not just the one token
// the client happens to be holding.
//
// A token that does not exist is not an error — the subquery yields no family
// and the UPDATE touches nothing.
func (s *Store) RevokeFamilyByToken(ctx context.Context, hash []byte, now time.Time) error {
	const query = `
		UPDATE refresh_tokens
		   SET revoked_at = ?
		 WHERE revoked_at IS NULL
		   AND family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = ?)`

	if _, err := s.db.ExecContext(ctx, query, now.Unix(), hash); err != nil {
		return fmt.Errorf("auth: revoke family: %w", err)
	}

	return nil
}

// RevokeAllForUser ends every session a user has. It has no endpoint yet; it is
// what a password change must call, and belongs with the queries it resembles.
func (s *Store) RevokeAllForUser(ctx context.Context, userID string, now time.Time) error {
	const query = `
		UPDATE refresh_tokens
		   SET revoked_at = ?
		 WHERE user_id = ? AND revoked_at IS NULL`

	if _, err := s.db.ExecContext(ctx, query, now.Unix(), userID); err != nil {
		return fmt.Errorf("auth: revoke user sessions: %w", err)
	}

	return nil
}

// DeleteExpired removes rows that can no longer authenticate anything.
//
// Spent and revoked tokens are kept until they expire rather than deleted
// immediately: reuse detection needs to find the spent row in order to
// recognise the reuse. Delete it early and a replayed token looks like an
// unknown one, which is exactly the signal being thrown away.
func (s *Store) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE expires_at <= ?`, now.Unix())
	if err != nil {
		return 0, fmt.Errorf("auth: delete expired tokens: %w", err)
	}

	removed, err := result.RowsAffected()
	if err != nil {
		return 0, nil
	}

	return removed, nil
}

// execer is satisfied by both *sql.DB and *sql.Tx, so insert can be used inside
// a rotation or on its own.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insert(ctx context.Context, db execer, token RefreshToken) error {
	const query = `
		INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, issued_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`

	_, err := db.ExecContext(ctx, query,
		token.ID, token.UserID, token.FamilyID, token.Hash,
		token.IssuedAt.Unix(), token.ExpiresAt.Unix())

	return err
}
