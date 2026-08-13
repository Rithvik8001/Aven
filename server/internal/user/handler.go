package user

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/rithvik/aven/server/internal/httpx"
)

// Handler serves the user endpoints.
type Handler struct {
	store  *Store
	logger *slog.Logger
}

// NewHandler builds a Handler.
func NewHandler(store *Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, logger: logger}
}

// Register mounts the user routes on mux.
//
// Method and path are matched together, a capability http.ServeMux gained in Go
// 1.22 — so a GET to this path returns 405 without any code of ours running.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/signup", h.Signup)
}

// Signup creates a new account.
//
//	201  the created user
//	400  the body could not be parsed
//	409  the email is already registered
//	415  the Content-Type was not JSON
//	422  the body parsed but failed validation
//	500  an unexpected failure
func (h *Handler) Signup(w http.ResponseWriter, r *http.Request) {
	var in SignupInput

	if err := httpx.Decode(w, r, &in); err != nil {
		// 415 rather than 400 when the media type is wrong: it tells the
		// client the body was never read, not that it was malformed.
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

	created, err := h.store.Create(r.Context(), in)
	if err != nil {
		h.handleCreateError(w, r, err)

		return
	}

	// Log the identifier, never the address or password. The ID is enough to
	// find the row when investigating.
	h.logger.InfoContext(r.Context(), "user registered", slog.String("user_id", created.ID))

	// 201 with a Location header pointing at the new resource, even though
	// the endpoint to fetch it does not exist yet.
	w.Header().Set("Location", "/api/v1/users/"+created.ID)
	httpx.Encode(w, http.StatusCreated, created)
}

// handleCreateError maps a store failure onto a response.
func (h *Handler) handleCreateError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, ErrEmailTaken) {
		// Signup necessarily reveals whether an address is registered —
		// the alternative is letting someone silently fail to sign up.
		// The defence against using this to enumerate accounts is rate
		// limiting, not a vague message.
		httpx.Error(w, http.StatusConflict, "email_taken",
			"An account with that email already exists.")

		return
	}

	// The real cause goes to the logs; the client gets a generic message so
	// no SQL or file path leaks into a public response.
	h.logger.ErrorContext(r.Context(), "failed to create user", slog.String("error", err.Error()))

	httpx.Error(w, http.StatusInternalServerError, "internal_error",
		"An unexpected error occurred.")
}
