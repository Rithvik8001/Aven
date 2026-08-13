// Package user handles user accounts: the model, its validation rules, storage,
// and the HTTP endpoints that expose them.
package user

import (
	"errors"
	"net/mail"
	"strings"
	"unicode/utf8"
)

// ErrEmailTaken is returned when an address is already registered. The store
// detects it from the unique index rather than checking first, which avoids a
// race where two concurrent signups both see the address as free.
var ErrEmailTaken = errors.New("user: email already registered")

// User is a registered account.
//
// The password hash is deliberately absent from the JSON tags: this struct is
// returned directly to clients, so a field that is never tagged can never be
// serialised by accident.
type User struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	CreatedAt   string `json:"created_at"`

	// PasswordHash stays server-side. json:"-" makes that explicit and
	// survives someone later adding tags to the whole struct.
	PasswordHash string `json:"-"`
}

// SignupInput is the request body for creating an account.
type SignupInput struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

// Password length bounds.
//
// The minimum follows NIST guidance: length is what matters, so there are no
// composition rules demanding a symbol and a digit — those push users toward
// predictable patterns without adding real entropy.
//
// The maximum is not arbitrary. bcrypt only considers the first 72 bytes of a
// password, so anything longer must be rejected rather than silently truncated,
// which would make two different long passwords equivalent.
const (
	MinPasswordLength = 8
	MaxPasswordBytes  = 72
)

const maxDisplayNameLength = 80

// Validate checks the input and returns a map of field name to reason.
//
// It returns every problem at once rather than the first, so a signup form can
// highlight all its invalid fields in a single round trip.
//
// It also normalises the input in place: whitespace is trimmed from the email
// and display name, since a trailing space in an address is always a typo. The
// password is never trimmed — leading and trailing spaces are legitimate
// characters in a passphrase.
func (in *SignupInput) Validate() map[string]string {
	problems := make(map[string]string)

	in.Email = strings.TrimSpace(in.Email)
	in.DisplayName = strings.TrimSpace(in.DisplayName)

	switch {
	case in.Email == "":
		problems["email"] = "is required"
	case len(in.Email) > 254:
		// The maximum length of an email address per RFC 5321.
		problems["email"] = "must be 254 characters or fewer"
	default:
		// net/mail implements the actual address grammar, which is far
		// more reliable than any regular expression.
		if _, err := mail.ParseAddress(in.Email); err != nil {
			problems["email"] = "must be a valid email address"
		}
	}

	switch {
	case in.Password == "":
		problems["password"] = "is required"
	// Counted in runes so a user of a non-Latin script is not penalised by a
	// byte-length minimum.
	case utf8.RuneCountInString(in.Password) < MinPasswordLength:
		problems["password"] = "must be at least 8 characters"
	// Counted in bytes, because that is the limit bcrypt actually applies.
	case len(in.Password) > MaxPasswordBytes:
		problems["password"] = "must be 72 bytes or fewer"
	}

	switch {
	case in.DisplayName == "":
		problems["display_name"] = "is required"
	case utf8.RuneCountInString(in.DisplayName) > maxDisplayNameLength:
		problems["display_name"] = "must be 80 characters or fewer"
	}

	if len(problems) == 0 {
		return nil
	}

	return problems
}
