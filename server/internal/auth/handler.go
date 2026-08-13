package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rithvik/aven/server/internal/httpx"
	"github.com/rithvik/aven/server/internal/user"
)

// refreshCookieName carries the refresh token.
//
// The __Host- prefix would be stronger still — browsers refuse to set it
// without Secure and a Path of "/", and no subdomain can overwrite it — but it
// also forbids the narrow Path below, and scoping the cookie to the auth routes
// is the more valuable of the two: it keeps the seven-day credential off every
// ordinary API request.
const refreshCookieName = "aven_refresh"

// refreshCookiePath limits which requests carry the refresh token.
//
// A cookie on "/" would be attached to every API call, so the long-lived
// credential would cross the wire hundreds of times a session instead of twice.
const refreshCookiePath = "/api/v1/auth"

// LoginInput is the request body for POST /api/v1/auth/login.
type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate checks only that the fields are present and sane in size.
//
// It deliberately does not apply the signup password rules. Those tighten over
// time, and an account created under the old ones must still be able to log in
// — a 422 telling a user their existing password is too short is a lockout, not
// a validation. Nor is the email parsed: a malformed address simply fails to
// match, and answering 401 rather than 422 keeps login from confirming which
// addresses are even well-formed enough to exist.
func (in *LoginInput) Validate() map[string]string {
	problems := make(map[string]string)

	in.Email = strings.TrimSpace(in.Email)

	if in.Email == "" {
		problems["email"] = "is required"
	}

	switch {
	case in.Password == "":
		problems["password"] = "is required"
	// bcrypt reads no further than 72 bytes, so anything longer cannot be a
	// password this system ever issued.
	case len(in.Password) > user.MaxPasswordBytes:
		problems["password"] = "must be 72 bytes or fewer"
	}

	if len(problems) == 0 {
		return nil
	}

	return problems
}

// tokenResponse is the success body for login and refresh.
//
// The refresh token is absent by design: it travels only in the Set-Cookie
// header, where script cannot read it. Putting it here too would undo the point
// of the HttpOnly flag.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	// ExpiresIn is seconds, following OAuth 2.0, so a client can schedule
	// its refresh without parsing the token.
	ExpiresIn int `json:"expires_in"`

	User *user.User `json:"user,omitempty"`
}

// Handler serves the authentication endpoints.
type Handler struct {
	service *Service
	logger  *slog.Logger

	// secureCookies sets the Secure flag. It is configuration rather than a
	// constant only so that a developer on http://localhost can still hold a
	// session; it must be true anywhere else.
	secureCookies bool
}

// NewHandler builds a Handler.
func NewHandler(service *Service, logger *slog.Logger, secureCookies bool) *Handler {
	return &Handler{service: service, logger: logger, secureCookies: secureCookies}
}

// Register mounts the auth routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", h.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", h.Refresh)
	mux.HandleFunc("POST /api/v1/auth/logout", h.Logout)

	// The only route behind the access token so far, and the reason the
	// token is verifiable end to end rather than in tests alone.
	mux.Handle("GET /api/v1/auth/me", RequireAccessToken(h.service.Issuer())(http.HandlerFunc(h.Me)))
}

// Login exchanges an email and password for a token pair.
//
//	200  an access token in the body, a refresh token in a cookie
//	400  the body could not be parsed
//	401  the email or password was wrong
//	415  the Content-Type was not JSON
//	422  a field was missing
//	500  an unexpected failure
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var in LoginInput

	if err := httpx.Decode(w, r, &in); err != nil {
		if errors.Is(err, httpx.ErrUnsupportedMediaType) {
			httpx.Error(w, http.StatusUnsupportedMediaType, "unsupported_media_type", err.Error())

			return
		}

		httpx.Error(w, http.StatusBadRequest, "invalid_request", err.Error())

		return
	}

	if problems := in.Validate(); problems != nil {
		httpx.ErrorWithDetails(w, http.StatusUnprocessableEntity,
			"validation_failed", "The request contains invalid fields.", problems)

		return
	}

	pair, account, err := h.service.Login(r.Context(), in)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			// Logged without the password and without saying which
			// half was wrong, because the logs are read by people
			// who should not learn that either.
			h.logger.WarnContext(r.Context(), "failed login")

			httpx.Error(w, http.StatusUnauthorized, "invalid_credentials",
				"The email or password is incorrect.")

			return
		}

		h.internalError(w, r, "login failed", err)

		return
	}

	h.logger.InfoContext(r.Context(), "user logged in", slog.String("user_id", account.ID))

	h.setRefreshCookie(w, pair)
	httpx.Encode(w, http.StatusOK, tokenResponse{
		AccessToken: pair.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(pair.AccessExpiresIn.Seconds()),
		User:        &account,
	})
}

// Refresh exchanges the refresh cookie for a new token pair.
//
//	200  a new access token, and a new refresh cookie replacing the old one
//	401  the cookie was missing, expired, revoked, or already spent
//	500  an unexpected failure
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(refreshCookieName)
	if err != nil || cookie.Value == "" {
		httpx.Error(w, http.StatusUnauthorized, "invalid_refresh_token",
			"The session has expired. Sign in again.")

		return
	}

	pair, err := h.service.Refresh(r.Context(), cookie.Value)
	if err != nil {
		h.handleRefreshError(w, r, err)

		return
	}

	h.setRefreshCookie(w, pair)
	httpx.Encode(w, http.StatusOK, tokenResponse{
		AccessToken: pair.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(pair.AccessExpiresIn.Seconds()),
	})
}

func (h *Handler) handleRefreshError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrRefreshReuse):
		// The one event here worth an alert: a spent token came back,
		// so either a token leaked or a client is refreshing in
		// parallel. The session is already gone by the time this runs.
		h.logger.ErrorContext(r.Context(), "refresh token reuse detected; session revoked")

	case errors.Is(err, ErrInvalidRefreshToken):
		h.logger.InfoContext(r.Context(), "refresh rejected")

	default:
		h.internalError(w, r, "refresh failed", err)

		return
	}

	// Clear the cookie on any rejection. Leaving a dead token in the browser
	// only guarantees the next request fails the same way.
	h.clearRefreshCookie(w)
	httpx.Error(w, http.StatusUnauthorized, "invalid_refresh_token",
		"The session has expired. Sign in again.")
}

// Logout revokes the session and clears the cookie.
//
// It answers 204 whether or not there was a session to end. Logout is not a
// query: a client clearing a stale cookie has done the right thing and has
// nothing to act on if told otherwise.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(refreshCookieName); err == nil && cookie.Value != "" {
		if err := h.service.Logout(r.Context(), cookie.Value); err != nil {
			// Clear the cookie regardless, then report the failure:
			// the row is still live server-side, which is a real
			// problem, and a silent 204 would hide it.
			h.clearRefreshCookie(w)
			h.internalError(w, r, "logout failed", err)

			return
		}
	}

	h.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// Me returns the account behind the presented access token.
//
//	200  the user
//	401  the access token was missing or invalid
//	500  an unexpected failure
//
// A 404 is impossible in practice and treated as a 401: a valid token whose
// subject no longer exists means a deleted account, and the credential should
// stop working rather than produce a confusing "not found".
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := SubjectFrom(r.Context())
	if !ok {
		// Unreachable unless the route is mounted without the
		// middleware, which is a wiring bug rather than a client error.
		h.internalError(w, r, "missing subject on authenticated route", errors.New("no subject in context"))

		return
	}

	account, err := h.service.Subject(r.Context(), userID)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			httpx.Error(w, http.StatusUnauthorized, "invalid_token",
				"The access token is invalid or has expired.")

			return
		}

		h.internalError(w, r, "failed to load user", err)

		return
	}

	httpx.Encode(w, http.StatusOK, account)
}

// setRefreshCookie writes the rotated refresh token.
//
// HttpOnly keeps it out of reach of script, so an XSS bug cannot walk away with
// a seven-day credential. SameSite=Strict means the browser never attaches it
// to a cross-site request, which is what stands in for a CSRF token on these
// endpoints. Secure keeps it off plaintext connections.
//
// MaxAge is derived from the token's own expiry rather than set independently,
// so the browser stops sending a token at the moment the server stops accepting
// it.
func (h *Handler) setRefreshCookie(w http.ResponseWriter, pair TokenPair) {
	maxAge := int(time.Until(pair.RefreshExpiryAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}

	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    pair.RefreshToken,
		Path:     refreshCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearRefreshCookie expires the cookie.
//
// Every attribute except Value and MaxAge must match the cookie that was set;
// a browser treats name, domain, and path as the identity of a cookie, so a
// mismatched Path deletes nothing and leaves the original in place.
func (h *Handler) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

// internalError logs the cause and returns a response that reveals none of it.
func (h *Handler) internalError(w http.ResponseWriter, r *http.Request, msg string, err error) {
	h.logger.ErrorContext(r.Context(), msg, slog.String("error", err.Error()))

	httpx.Error(w, http.StatusInternalServerError, "internal_error",
		"An unexpected error occurred.")
}
