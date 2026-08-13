package user_test

import (
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/rithvik/aven/server/internal/database"
	"github.com/rithvik/aven/server/internal/user"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	valid := user.SignupInput{
		Email:       "ada@example.com",
		Password:    "correct horse battery",
		DisplayName: "Ada Lovelace",
	}

	tests := map[string]struct {
		mutate    func(*user.SignupInput)
		wantField string
	}{
		"valid input":      {mutate: func(*user.SignupInput) {}},
		"missing email":    {mutate: func(in *user.SignupInput) { in.Email = "" }, wantField: "email"},
		"malformed email":  {mutate: func(in *user.SignupInput) { in.Email = "not-an-email" }, wantField: "email"},
		"missing password": {mutate: func(in *user.SignupInput) { in.Password = "" }, wantField: "password"},
		"short password":   {mutate: func(in *user.SignupInput) { in.Password = "sh0rt" }, wantField: "password"},
		"missing name":     {mutate: func(in *user.SignupInput) { in.DisplayName = "" }, wantField: "display_name"},
		"overlong name":    {mutate: func(in *user.SignupInput) { in.DisplayName = strings.Repeat("a", 81) }, wantField: "display_name"},
		// bcrypt ignores everything past 72 bytes, so a longer password must
		// be rejected rather than silently truncated.
		"password over 72 bytes": {
			mutate:    func(in *user.SignupInput) { in.Password = strings.Repeat("x", 73) },
			wantField: "password",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			in := valid
			tt.mutate(&in)

			problems := in.Validate()

			if tt.wantField == "" {
				if problems != nil {
					t.Fatalf("Validate() = %v, want no problems", problems)
				}

				return
			}

			if _, ok := problems[tt.wantField]; !ok {
				t.Errorf("Validate() = %v, want a problem for %q", problems, tt.wantField)
			}
		})
	}
}

// TestValidateTrimsWhitespace covers the normalisation contract: the email and
// name are trimmed, but the password is left exactly as typed.
func TestValidateTrimsWhitespace(t *testing.T) {
	t.Parallel()

	in := user.SignupInput{
		Email:       "  ada@example.com  ",
		Password:    " has spaces ",
		DisplayName: "  Ada  ",
	}

	if problems := in.Validate(); problems != nil {
		t.Fatalf("Validate() = %v, want no problems", problems)
	}

	if in.Email != "ada@example.com" {
		t.Errorf("Email = %q, want it trimmed", in.Email)
	}

	if in.DisplayName != "Ada" {
		t.Errorf("DisplayName = %q, want it trimmed", in.DisplayName)
	}

	if in.Password != " has spaces " {
		t.Errorf("Password = %q, want it untouched", in.Password)
	}
}

func TestSignup(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body        string
		contentType string
		wantStatus  int
		wantCode    string
	}{
		"valid signup": {
			body:       `{"email":"ada@example.com","password":"correct horse","display_name":"Ada"}`,
			wantStatus: http.StatusCreated,
		},
		"invalid email": {
			body:       `{"email":"nope","password":"correct horse","display_name":"Ada"}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "validation_failed",
		},
		"malformed json": {
			body:       `{"email":`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		"empty body": {
			body:       ``,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		// A client typo must be reported, not silently ignored.
		"unknown field": {
			body:       `{"email":"a@b.co","password":"correct horse","display_name":"A","admin":true}`,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		"wrong content type": {
			body:        `email=ada@example.com`,
			contentType: "application/x-www-form-urlencoded",
			wantStatus:  http.StatusUnsupportedMediaType,
			wantCode:    "unsupported_media_type",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := newTestHandler(t)

			contentType := tt.contentType
			if contentType == "" {
				contentType = "application/json"
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(tt.body))
			r.Header.Set("Content-Type", contentType)

			handler.Signup(w, r)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body)
			}

			if tt.wantCode == "" {
				return
			}

			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}

			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("error response is not valid JSON: %v", err)
			}

			if body.Error.Code != tt.wantCode {
				t.Errorf("error.code = %q, want %q", body.Error.Code, tt.wantCode)
			}
		})
	}
}

// TestSignupNeverReturnsPasswordHash is the security-critical assertion: the
// hash must not appear in the response under any field name.
func TestSignupNeverReturnsPasswordHash(t *testing.T) {
	t.Parallel()

	w := signup(t, newTestHandler(t), `{"email":"ada@example.com","password":"correct horse","display_name":"Ada"}`)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	for _, forbidden := range []string{"password", "hash", "$2a$"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Errorf("response contains %q: %s", forbidden, w.Body)
		}
	}
}

// TestSignupStoresBcryptHash verifies the password is hashed rather than stored,
// and that the stored hash actually verifies against the original.
func TestSignupStoresBcryptHash(t *testing.T) {
	t.Parallel()

	db := newTestDB(t)
	handler := user.NewHandler(user.NewStore(db), discardLogger())

	const password = "correct horse battery"

	if w := signup(t, handler, `{"email":"ada@example.com","password":"`+password+`","display_name":"Ada"}`); w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	var stored string
	if err := db.QueryRow(`SELECT password_hash FROM users`).Scan(&stored); err != nil {
		t.Fatalf("failed to read stored hash: %v", err)
	}

	if stored == password {
		t.Fatal("the password was stored in plaintext")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)); err != nil {
		t.Errorf("stored hash does not verify against the original password: %v", err)
	}
}

// TestSignupRejectsDuplicateEmail also covers case-insensitivity: the unique
// index is on lower(email), so a different capitalisation must still collide.
func TestSignupRejectsDuplicateEmail(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)

	if w := signup(t, handler, `{"email":"ada@example.com","password":"correct horse","display_name":"Ada"}`); w.Code != http.StatusCreated {
		t.Fatalf("first signup: status = %d, want %d", w.Code, http.StatusCreated)
	}

	w := signup(t, handler, `{"email":"ADA@example.com","password":"different pass","display_name":"Ada"}`)

	if w.Code != http.StatusConflict {
		t.Fatalf("second signup: status = %d, want %d (body: %s)", w.Code, http.StatusConflict, w.Body)
	}

	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}

	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error response is not valid JSON: %v", err)
	}

	if body.Error.Code != "email_taken" {
		t.Errorf("error.code = %q, want %q", body.Error.Code, "email_taken")
	}
}

// TestRegisterRejectsWrongMethod confirms ServeMux answers 405 for a method
// mismatch without any handler code running.
func TestRegisterRejectsWrongMethod(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	newTestHandler(t).Register(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/auth/signup", nil))

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func signup(t *testing.T, handler *user.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	handler.Signup(w, r)

	return w
}

func newTestHandler(t *testing.T) *user.Handler {
	t.Helper()

	return user.NewHandler(user.NewStore(newTestDB(t)), discardLogger())
}

// newTestDB opens a database in the test's temporary directory, which t.TempDir
// removes automatically. A real file rather than :memory: so the test exercises
// the same schema and index behaviour as production.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := database.Open(t.Context(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("database.Open() failed: %v", err)
	}

	t.Cleanup(func() { db.Close() })

	return db
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
