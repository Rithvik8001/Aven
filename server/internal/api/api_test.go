package api_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/rithvik/aven/server/internal/api"
	"github.com/rithvik/aven/server/internal/database"
)

func TestHealth(t *testing.T) {
	db, err := database.Open(t.Context(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	defer db.Close()

	handler := api.New(db, slog.New(slog.NewTextHandler(io.Discard, nil))).Routes()

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	if got, want := w.Body.String(), `{"status":"ok"}`+"\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}
