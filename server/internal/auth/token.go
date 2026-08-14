package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/google/uuid"
)

// MinSecretBytes is the shortest signing key accepted.
//
// HS256 is HMAC-SHA-256, whose security is capped by the block size of the
// hash; a key shorter than 32 bytes is the weak link, and a short one is
// usually a placeholder that reached production by accident.
const MinSecretBytes = 32

// signingMethod is pinned rather than read from the token header.
//
// Reading the algorithm from the token is the classic JWT vulnerability: an
// attacker changes it to "none", or to HS256 on a service that verifies with an
// RSA public key, and forges tokens at will. The verifier below only ever
// accepts this one.
var signingMethod = jwt.SigningMethodHS256

// ErrInvalidAccessToken is returned when a token is missing, malformed,
// expired, signed with the wrong key, or signed with an unexpected algorithm.
// The distinction matters to no client, so it is not exposed.
var ErrInvalidAccessToken = errors.New("auth: invalid access token")

// accessTokenUse is the value of the "token_use" claim.
//
// Only access tokens are JWTs today, so nothing can currently be confused for
// one — the claim is here so that when a second kind of JWT appears (an email
// verification link, say) it cannot be replayed as a session credential.
const accessTokenUse = "access"

// Claims is what an access token carries.
//
// It is deliberately thin: the subject and nothing else. Every extra claim is a
// copy of data that goes stale the moment the row changes, and a token cannot
// be un-issued — a display name embedded here would keep showing the old value
// for up to fifteen minutes after the user changed it.
type Claims struct {
	jwt.RegisteredClaims

	TokenUse string `json:"token_use"`
}

// defaultKeyID is the "kid" a token carries when the caller never configured
// one. It keeps the common single-key deployment free of any new
// configuration: nothing has to name a key until a second one exists to be
// confused with it.
const defaultKeyID = "1"

// signingKey pairs a secret with the "kid" a token carries so Verify can find
// it again without trying every key on hand.
type signingKey struct {
	id     string
	secret []byte
}

// Issuer mints and verifies access tokens.
//
// It holds at most two keys: current signs new tokens and verifies them;
// previous, if set, only verifies. That is what makes rotation possible
// without a service-wide outage — tokens signed just before a rotation stay
// valid for the rest of their short lifetime instead of being rejected the
// moment the key changes.
type Issuer struct {
	current  signingKey
	previous *signingKey
	issuer   string
	ttl      time.Duration
}

// NewIssuer validates the configuration and builds an Issuer.
func NewIssuer(cfg Config) (*Issuer, error) {
	if len(cfg.Secret) < MinSecretBytes {
		return nil, fmt.Errorf("auth: signing secret must be at least %d bytes, got %d",
			MinSecretBytes, len(cfg.Secret))
	}

	if cfg.Issuer == "" {
		return nil, errors.New("auth: issuer must not be empty")
	}

	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = DefaultAccessTokenTTL
	}

	keyID := cfg.KeyID
	if keyID == "" {
		keyID = defaultKeyID
	}

	issuer := &Issuer{
		current: signingKey{id: keyID, secret: copyBytes(cfg.Secret)},
		issuer:  cfg.Issuer,
		ttl:     cfg.AccessTokenTTL,
	}

	if len(cfg.PreviousSecret) > 0 {
		if len(cfg.PreviousSecret) < MinSecretBytes {
			return nil, fmt.Errorf("auth: previous signing secret must be at least %d bytes, got %d",
				MinSecretBytes, len(cfg.PreviousSecret))
		}

		if cfg.PreviousKeyID == "" {
			return nil, errors.New("auth: previous key id must not be empty when a previous secret is set")
		}

		// A collision here would mean the previous key silently wins or
		// loses depending on map iteration — better to refuse to start
		// than to guess which key an operator meant.
		if cfg.PreviousKeyID == keyID {
			return nil, errors.New("auth: previous key id must differ from the current key id")
		}

		issuer.previous = &signingKey{id: cfg.PreviousKeyID, secret: copyBytes(cfg.PreviousSecret)}
	}

	return issuer, nil
}

// copyBytes returns a copy of b: the caller may hold the only reference to a
// slice it later zeroes or reuses.
func copyBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)

	return out
}

// Issue signs an access token for userID and reports its lifetime.
func (i *Issuer) Issue(userID string, now time.Time) (string, time.Duration, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   i.issuer,
			Subject:  userID,
			IssuedAt: jwt.NewNumericDate(now),
			// NotBefore matches IssuedAt: there is no case where a token
			// should be valid later than it was minted.
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
			// A unique ID per token, so a specific token can be traced
			// through the logs and denylisted if that is ever needed.
			ID: newID(),
		},
		TokenUse: accessTokenUse,
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	// kid names which key signed the token, so Verify can find it again
	// after a rotation swaps in a new current key.
	token.Header["kid"] = i.current.id

	signed, err := token.SignedString(i.current.secret)
	if err != nil {
		return "", 0, fmt.Errorf("auth: sign access token: %w", err)
	}

	return signed, i.ttl, nil
}

// Verify checks a token and returns its subject.
//
// It returns only ErrInvalidAccessToken: the caller answers 401 either way, and
// a detailed reason on the wire tells an attacker which part of a forgery to
// fix next.
func (i *Issuer) Verify(token string) (string, error) {
	parsed, err := jwt.ParseWithClaims(token, &Claims{},
		func(t *jwt.Token) (any, error) {
			kid, _ := t.Header["kid"].(string)

			switch {
			case kid == i.current.id:
				return i.current.secret, nil
			case i.previous != nil && kid == i.previous.id:
				return i.previous.secret, nil
			default:
				// An unrecognized kid fails closed rather than falling
				// back to "try every key": that fallback is exactly the
				// ambiguity a kid exists to remove.
				return nil, ErrInvalidAccessToken
			}
		},
		// WithValidMethods is the algorithm pin. Without it the keyfunc
		// above would happily hand the HMAC secret to a token that asked
		// to be verified some other way.
		jwt.WithValidMethods([]string{signingMethod.Alg()}),
		jwt.WithIssuer(i.issuer),
		// Every token we mint has an exp; requiring one means a token
		// that somehow lacks it is rejected rather than treated as
		// eternal.
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return "", ErrInvalidAccessToken
	}

	claims, ok := parsed.Claims.(*Claims)
	if !ok || claims.TokenUse != accessTokenUse || claims.Subject == "" {
		return "", ErrInvalidAccessToken
	}

	return claims.Subject, nil
}

// refreshSecretBytes is the entropy behind a refresh token.
//
// The token is guessable only by brute force, so 256 bits puts that firmly out
// of reach and leaves no reason to add a rate limit on the guessing.
const refreshSecretBytes = 32

// newRefreshSecret returns a fresh random token, URL-safe so it survives a
// cookie value and a header without encoding.
func newRefreshSecret() (string, error) {
	buf := make([]byte, refreshSecretBytes)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generate refresh token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// hashToken returns what is stored in place of the token itself.
//
// A plain SHA-256, not bcrypt: the input is 256 bits of uniform randomness, so
// there is no dictionary to defend against, and the lookup has to be a fast
// indexed equality test rather than a comparison against every row. What this
// buys is that a dump of the table contains nothing usable — the hashes cannot
// be replayed as tokens.
func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))

	return sum[:]
}

// newID generates a time-ordered identifier.
//
// It panics only if the system random source has failed, at which point the
// process cannot mint safe credentials and must not carry on pretending it can.
// The recovery middleware turns it into a 500.
func newID() string {
	id, err := uuid.NewV7()
	if err != nil {
		panic(fmt.Sprintf("auth: generate uuid: %v", err))
	}

	return id.String()
}
