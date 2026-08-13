package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/rithvik/aven/server/internal/httpx"
)

// contextKey is unexported so nothing outside this package can write the
// subject into a context. A string key would let any package — or any
// dependency — overwrite the authenticated identity by accident.
type contextKey struct{}

var subjectKey contextKey

// SubjectFrom returns the authenticated user's ID, if the request passed
// through RequireAccessToken.
func SubjectFrom(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(subjectKey).(string)

	return userID, ok
}

// RequireAccessToken rejects any request without a valid access token and puts
// the token's subject in the request context for the handler behind it.
//
// It is a middleware constructor rather than a method on Handler so a route can
// be protected without depending on the auth endpoints.
func RequireAccessToken(issuer *Issuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r)
			if !ok {
				unauthorized(w, "The request requires a bearer token.")

				return
			}

			userID, err := issuer.Verify(token)
			if err != nil {
				unauthorized(w, "The access token is invalid or has expired.")

				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), subjectKey, userID)))
		})
	}
}

// bearerToken extracts the credential from an Authorization header.
//
// The scheme is compared case-insensitively because RFC 7235 defines it that
// way, and clients do send "bearer".
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")

	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}

	token = strings.TrimSpace(token)

	return token, token != ""
}

// unauthorized answers 401 with the challenge the status requires.
//
// A bare 401 is incomplete: RFC 9110 requires a WWW-Authenticate header, and it
// is what tells a client which scheme to retry with.
func unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="aven"`)

	httpx.Error(w, http.StatusUnauthorized, "invalid_token", message)
}
