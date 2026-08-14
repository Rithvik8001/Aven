package post

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/rithvik/aven/server/internal/auth"
	"github.com/rithvik/aven/server/internal/httpx"
)

type Handler struct {
	store  *Store
	issuer *auth.Issuer
	logger *slog.Logger
}

func NewHandler(store *Store, issuer *auth.Issuer, logger *slog.Logger) *Handler {
	return &Handler{store: store, issuer: issuer, logger: logger}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/posts", h.ListPublished)
	mux.HandleFunc("GET /api/v1/posts/{slug}", h.GetBySlug)
	mux.Handle("POST /api/v1/posts", auth.RequireAccessToken(h.issuer)(http.HandlerFunc(h.Create)))
	mux.Handle("GET /api/v1/me/posts", auth.RequireAccessToken(h.issuer)(http.HandlerFunc(h.ListMine)))
	mux.Handle("PUT /api/v1/posts/{id}", auth.RequireAccessToken(h.issuer)(http.HandlerFunc(h.Update)))
	mux.Handle("DELETE /api/v1/posts/{id}", auth.RequireAccessToken(h.issuer)(http.HandlerFunc(h.Delete)))
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var in CreateInput
	if !decode(w, r, &in) {
		return
	}
	if problems := in.Validate(); problems != nil {
		httpx.ErrorWithDetails(w, http.StatusUnprocessableEntity, "validation_failed", "The request contains invalid fields.", problems)
		return
	}
	authorID, ok := subject(w, r)
	if !ok {
		return
	}
	created, err := h.store.Create(r.Context(), authorID, in)
	if err != nil {
		handleStoreError(w, r, h.logger, "create post", err)
		return
	}
	h.logger.InfoContext(r.Context(), "post created", slog.String("post_id", created.ID), slog.String("user_id", authorID))
	w.Header().Set("Location", "/api/v1/posts/"+created.Slug)
	httpx.Encode(w, http.StatusCreated, created)
}

func (h *Handler) GetBySlug(w http.ResponseWriter, r *http.Request) {
	found, err := h.store.BySlug(r.Context(), r.PathValue("slug"))
	if errors.Is(err, ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "post_not_found", "The post was not found.")
		return
	}
	if err != nil {
		handleStoreError(w, r, h.logger, "get post", err)
		return
	}
	httpx.Encode(w, http.StatusOK, found)
}

func (h *Handler) ListPublished(w http.ResponseWriter, r *http.Request) {
	page, err := parsePage(r)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	result, err := h.store.ListPublished(r.Context(), page)
	if err != nil {
		handleStoreError(w, r, h.logger, "list published posts", err)
		return
	}
	httpx.Encode(w, http.StatusOK, result)
}

func (h *Handler) ListMine(w http.ResponseWriter, r *http.Request) {
	authorID, ok := subject(w, r)
	if !ok {
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && status != StatusDraft && status != StatusPublished {
		httpx.Error(w, http.StatusBadRequest, "invalid_status", "Status must be draft or published.")
		return
	}
	page, err := parsePage(r)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_pagination", err.Error())
		return
	}
	result, err := h.store.ListMine(r.Context(), authorID, status, page)
	if err != nil {
		handleStoreError(w, r, h.logger, "list own posts", err)
		return
	}
	httpx.Encode(w, http.StatusOK, result)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	var in UpdateInput
	if !decode(w, r, &in) {
		return
	}
	if problems := in.Validate(); problems != nil {
		httpx.ErrorWithDetails(w, http.StatusUnprocessableEntity, "validation_failed", "The request contains invalid fields.", problems)
		return
	}
	authorID, ok := subject(w, r)
	if !ok {
		return
	}
	updated, err := h.store.Update(r.Context(), r.PathValue("id"), authorID, in)
	if err != nil {
		handleStoreError(w, r, h.logger, "update post", err)
		return
	}
	h.logger.InfoContext(r.Context(), "post updated", slog.String("post_id", updated.ID), slog.String("user_id", authorID))
	httpx.Encode(w, http.StatusOK, updated)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	authorID, ok := subject(w, r)
	if !ok {
		return
	}
	if err := h.store.Delete(r.Context(), r.PathValue("id"), authorID); err != nil {
		handleStoreError(w, r, h.logger, "delete post", err)
		return
	}
	h.logger.InfoContext(r.Context(), "post deleted", slog.String("post_id", r.PathValue("id")), slog.String("user_id", authorID))
	w.WriteHeader(http.StatusNoContent)
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httpx.Decode(w, r, dst); err != nil {
		if errors.Is(err, httpx.ErrUnsupportedMediaType) {
			httpx.Error(w, http.StatusUnsupportedMediaType, "unsupported_media_type", err.Error())
		} else {
			httpx.Error(w, http.StatusBadRequest, "invalid_request", err.Error())
		}
		return false
	}
	return true
}

func subject(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, ok := auth.SubjectFrom(r.Context())
	if !ok || id == "" {
		httpx.Error(w, http.StatusInternalServerError, "internal_error", "An unexpected error occurred.")
		return "", false
	}
	return id, true
}

func parsePage(r *http.Request) (Page, error) {
	limit := 20
	if value := r.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			return Page{}, errors.New("limit must be between 1 and 100")
		}
		limit = parsed
	}
	var cursor Cursor
	if value := r.URL.Query().Get("cursor"); value != "" {
		var err error
		cursor, err = DecodeCursor(value)
		if err != nil {
			return Page{}, err
		}
	}
	return Page{Limit: limit, Cursor: cursor}, nil
}

func handleStoreError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, operation string, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.Error(w, http.StatusNotFound, "post_not_found", "The post was not found.")
	case errors.Is(err, ErrSlugTaken):
		httpx.Error(w, http.StatusConflict, "slug_taken", "A post with that slug already exists.")
	default:
		logger.ErrorContext(r.Context(), operation+" failed", slog.String("error", err.Error()))
		httpx.Error(w, http.StatusInternalServerError, "internal_error", "An unexpected error occurred.")
	}
}
