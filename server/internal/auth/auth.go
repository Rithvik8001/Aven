// Package auth issues and verifies the credentials a client uses after signup:
// a short-lived JWT access token and a long-lived opaque refresh token.
//
// The two are deliberately different kinds of thing. The access token is a
// signed statement that anyone holding the key can verify without a database
// round trip, which is what makes it cheap enough to check on every request —
// and it is short-lived precisely because nothing can revoke it once issued.
// The refresh token is the opposite: a random string with no meaning of its own,
// stored server-side, so it can be revoked the moment something looks wrong.
//
// Making the refresh token a second JWT would be simpler and wrong: a stolen
// one would stay valid for its full seven days with no way to stop it.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/rithvik/aven/server/internal/user"
)

// Errors returned by Service. Handlers map these onto status codes; the client
// is never told which one occurred beyond "your credentials are no good",
// because the difference is exactly what an attacker wants to learn.
var (
	// ErrInvalidCredentials covers both an unknown email and a wrong
	// password. One error for both cases is what stops login from being an
	// oracle for which addresses are registered.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")

	// ErrInvalidRefreshToken means the presented token is unknown, expired,
	// or revoked.
	ErrInvalidRefreshToken = errors.New("auth: invalid refresh token")

	// ErrRefreshReuse means a token that was already spent came back. That
	// should be impossible for an honest client, so it is treated as
	// evidence of theft: the whole token family is revoked. It is separate
	// from ErrInvalidRefreshToken so the handler can log it loudly, not so
	// the client can see the difference.
	ErrRefreshReuse = errors.New("auth: refresh token reused")
)

// Default token lifetimes.
//
// Fifteen minutes for the access token is the usual compromise: long enough
// that a client is not refreshing constantly, short enough that a leaked token
// is stale before it is useful. Seven days for the refresh token bounds how
// long an idle session survives.
const (
	DefaultAccessTokenTTL  = 15 * time.Minute
	DefaultRefreshTokenTTL = 7 * 24 * time.Hour
)

// Config holds everything the service needs that comes from the environment.
type Config struct {
	// Secret signs access tokens. It must be at least MinSecretBytes long.
	Secret []byte

	// KeyID names Secret in a token's "kid" header. It defaults to a fixed
	// value when empty, so a deployment with no previous key needs no
	// configuration here at all.
	KeyID string

	// PreviousSecret, if set, is still accepted for verifying tokens signed
	// before a rotation, but is never used to sign new ones. Leave it empty
	// outside of a rotation window.
	PreviousSecret []byte

	// PreviousKeyID names PreviousSecret. Required, and must differ from
	// KeyID, whenever PreviousSecret is set.
	PreviousKeyID string

	// Issuer is the "iss" claim, and is verified on the way back in. It
	// stops a token minted by a sibling service that happens to share the
	// key from being accepted here.
	Issuer string

	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// UserFinder is the slice of the user store this package needs.
//
// It is declared here, at the point of use, rather than exported from the user
// package: auth depends on user, never the reverse, and a two-method interface
// is all a test needs to stand in for.
type UserFinder interface {
	ByEmail(ctx context.Context, email string) (user.User, error)
	ByID(ctx context.Context, id string) (user.User, error)
}

// Service performs the authentication operations. It owns no HTTP concerns;
// Handler adapts it to the wire.
type Service struct {
	users  UserFinder
	tokens *Store
	issuer *Issuer
	ttl    time.Duration
}

// NewService builds a Service. It returns an error rather than panicking on a
// bad config so the process can report the problem and exit cleanly at startup.
func NewService(users UserFinder, tokens *Store, cfg Config) (*Service, error) {
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = DefaultRefreshTokenTTL
	}

	issuer, err := NewIssuer(cfg)
	if err != nil {
		return nil, err
	}

	return &Service{
		users:  users,
		tokens: tokens,
		issuer: issuer,
		ttl:    cfg.RefreshTokenTTL,
	}, nil
}

// Issuer exposes the token verifier so middleware can be built from the same
// configuration that mints the tokens, rather than a second copy of it.
func (s *Service) Issuer() *Issuer { return s.issuer }

// TokenPair is what a successful login or refresh produces.
type TokenPair struct {
	AccessToken string
	// AccessExpiresIn is the access token's lifetime, which the client uses
	// to schedule a refresh before it lapses.
	AccessExpiresIn time.Duration

	// RefreshToken is the raw secret. It exists in this struct and in the
	// Set-Cookie header and nowhere else — only its hash is persisted.
	RefreshToken    string
	RefreshExpiryAt time.Time
}

// dummyHash is compared against when no user matches the submitted email.
//
// Without it, a request for an unknown address returns as soon as the SELECT
// misses, while a request for a known address takes the ~300ms bcrypt needs.
// That difference is measurable over the network, and turns login into a way to
// enumerate registered addresses. Hashing a throwaway password makes both paths
// cost the same.
//
// It is a real bcrypt hash of a value nobody knows, generated once at startup.
var dummyHash []byte

func init() {
	// Cost 12 to match the store, so the decoy costs what the real path
	// costs. Generated rather than hard-coded so it cannot drift out of
	// step with the cost the store actually uses.
	hash, err := bcrypt.GenerateFromPassword([]byte("aven-timing-equalisation-decoy"), 12)
	if err != nil {
		panic(fmt.Sprintf("auth: generate dummy hash: %v", err))
	}

	dummyHash = hash
}

// Login verifies an email and password and issues a fresh token pair.
//
// The new refresh token starts a new family: every token later derived from it
// by rotation carries the same family ID, so revoking the family ends the whole
// session at once.
func (s *Service) Login(ctx context.Context, in LoginInput) (TokenPair, user.User, error) {
	found, err := s.users.ByEmail(ctx, in.Email)

	switch {
	case err == nil:
	case errors.Is(err, user.ErrNotFound):
		// Burn the same CPU the real path would, then fail. The compare
		// is guaranteed to fail; it is here only for its cost.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(in.Password))

		return TokenPair{}, user.User{}, ErrInvalidCredentials
	default:
		return TokenPair{}, user.User{}, fmt.Errorf("auth: look up user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(found.PasswordHash), []byte(in.Password)); err != nil {
		// Any bcrypt failure is a failed login. Distinguishing a
		// mismatch from a malformed stored hash would tell the client
		// something about the account it should not learn.
		return TokenPair{}, user.User{}, ErrInvalidCredentials
	}

	now := time.Now().UTC()

	pair, refresh, err := s.mint(found.ID, newID(), now)
	if err != nil {
		return TokenPair{}, user.User{}, err
	}

	if err := s.tokens.Create(ctx, refresh); err != nil {
		return TokenPair{}, user.User{}, fmt.Errorf("auth: store refresh token: %w", err)
	}

	return pair, found, nil
}

// Refresh exchanges a refresh token for a new pair and invalidates the old one.
//
// Rotation on every use is what makes theft detectable: if the same token is
// presented twice, one of the two presenters is not the client, and Rotate
// revokes the family rather than trying to guess which.
func (s *Service) Refresh(ctx context.Context, presented string) (TokenPair, error) {
	hash := hashToken(presented)
	now := time.Now().UTC()

	// The new token's material is generated before the swap so the store can
	// consume the old row and insert the new one in a single transaction.
	pair, next, err := s.mint("", "", now)
	if err != nil {
		return TokenPair{}, err
	}

	userID, err := s.tokens.Rotate(ctx, hash, next, now)
	if err != nil {
		return TokenPair{}, err
	}

	// Rotate filled in the owner and family from the consumed row, so the
	// access token can only now be signed for the right subject.
	access, expiresIn, err := s.issuer.Issue(userID, now)
	if err != nil {
		return TokenPair{}, err
	}

	pair.AccessToken = access
	pair.AccessExpiresIn = expiresIn

	return pair, nil
}

// Logout revokes the family the presented token belongs to, ending the session
// on every device that shares it.
//
// An unknown token is not an error. Logout is the one operation that must
// always appear to succeed: a client clearing a stale cookie has nothing to fix
// and no reason to be told it failed.
func (s *Service) Logout(ctx context.Context, presented string) error {
	if presented == "" {
		return nil
	}

	if err := s.tokens.RevokeFamilyByToken(ctx, hashToken(presented), time.Now().UTC()); err != nil {
		return fmt.Errorf("auth: revoke session: %w", err)
	}

	return nil
}

// Subject returns the account behind a verified access token's subject claim.
func (s *Service) Subject(ctx context.Context, userID string) (user.User, error) {
	return s.users.ByID(ctx, userID)
}

// mint generates a token pair and the row that will back its refresh token.
//
// userID and familyID are empty when refreshing, because both are only known
// once the presented token has been consumed; Rotate fills them in.
func (s *Service) mint(userID, familyID string, now time.Time) (TokenPair, RefreshToken, error) {
	secret, err := newRefreshSecret()
	if err != nil {
		return TokenPair{}, RefreshToken{}, err
	}

	refresh := RefreshToken{
		ID:        newID(),
		UserID:    userID,
		FamilyID:  familyID,
		Hash:      hashToken(secret),
		IssuedAt:  now,
		ExpiresAt: now.Add(s.ttl),
	}

	pair := TokenPair{
		RefreshToken:    secret,
		RefreshExpiryAt: refresh.ExpiresAt,
	}

	// On the login path the subject is already known, so sign now. On the
	// refresh path the caller signs once Rotate reveals the owner.
	if userID != "" {
		access, expiresIn, err := s.issuer.Issue(userID, now)
		if err != nil {
			return TokenPair{}, RefreshToken{}, err
		}

		pair.AccessToken = access
		pair.AccessExpiresIn = expiresIn
	}

	return pair, refresh, nil
}
