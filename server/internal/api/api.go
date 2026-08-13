// Package api defines the HTTP routes and their handlers.
package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
)

// API holds the dependencies the handlers need.
type API struct {
	db     *sql.DB
	logger *slog.Logger
}

// New builds an API.
func New(db *sql.DB, logger *slog.Logger) *API {
	return &API{db: db, logger: logger}
}

// Routes returns the router with every route registered.
//
// The router is the standard library's http.ServeMux. Since Go 1.22 it matches
// on method and supports path wildcards ("GET /api/v1/posts/{slug}"), so a
// third-party router is not needed.
func (a *API) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", a.health)

	return mux
}

// health reports whether the service and its database are working.
func (a *API) health(w http.ResponseWriter, r *http.Request) {
	if err := a.db.PingContext(r.Context()); err != nil {
		a.logger.ErrorContext(r.Context(), "database health check failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "down"})

		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// writeJSON sends v as a JSON response.
//
// The Content-Type header is set before WriteHeader on purpose: headers written
// after the status line are silently dropped.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// The response is already committed by this point, so a failure here
	// cannot be reported to the client.
	_ = json.NewEncoder(w).Encode(v)
}
