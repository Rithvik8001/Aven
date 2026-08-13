// Package httpx holds the JSON request and response helpers shared by handlers.
//
// Every endpoint decodes and replies through these functions, so the wire format
// is defined once rather than re-invented per handler.
package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxRequestBody caps a decoded request body so a hostile client cannot exhaust
// memory. Signup payloads are a few hundred bytes.
const maxRequestBody = 64 << 10 // 64 KiB

// ErrUnsupportedMediaType is returned by Decode when the request did not declare
// JSON. It is a distinct sentinel so a caller can answer 415 rather than 400,
// which tells the client the body was never read at all.
var ErrUnsupportedMediaType = errors.New("Content-Type must be application/json.")

// ErrorResponse is the single shape every failed request returns, so the client
// can write one error handler for the whole API.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody carries the client-facing detail of a failure.
type ErrorBody struct {
	// Code is stable and machine-readable, such as "email_taken". Clients
	// branch on this, never on Message.
	Code string `json:"code"`
	// Message is human-readable and safe to display.
	Message string `json:"message"`
	// Details maps a field name to why it was rejected.
	Details map[string]string `json:"details,omitempty"`
}

// Encode writes v as JSON with the given status.
func Encode(w http.ResponseWriter, status int, v any) {
	// Marshal before touching the ResponseWriter, so a failure is caught
	// while the response is still uncommitted.
	body, err := json.Marshal(v)
	if err != nil {
		Error(w, http.StatusInternalServerError, "internal_error", "An unexpected error occurred.")

		return
	}

	// Headers set after WriteHeader are silently dropped.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	// The response is committed by now, so a write failure — almost always a
	// disconnected client — cannot be reported.
	_, _ = w.Write(body)
}

// Error replies with the standard error envelope.
func Error(w http.ResponseWriter, status int, code, message string) {
	ErrorWithDetails(w, status, code, message, nil)
}

// ErrorWithDetails replies with the error envelope plus per-field reasons.
func ErrorWithDetails(w http.ResponseWriter, status int, code, message string, details map[string]string) {
	body, err := json.Marshal(ErrorResponse{
		Error: ErrorBody{Code: code, Message: message, Details: details},
	})
	if err != nil {
		// Marshalling plain strings cannot realistically fail, and there
		// is no second error response to fall back to.
		http.Error(w, `{"error":{"code":"internal_error"}}`, http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	_, _ = w.Write(body)
}

// Decode reads a JSON request body into dst.
//
// It adds the protections a bare json.Decode lacks: the Content-Type is checked,
// the body is size-capped, unknown fields are rejected so a client typo is
// reported rather than ignored, and trailing data is rejected so a second
// concatenated object cannot slip past validation.
//
// The returned error is a message meant to be shown to the client, which is why
// it breaks the usual Go convention of lowercase, unpunctuated error strings.
func Decode(w http.ResponseWriter, r *http.Request, dst any) error {
	// The header may carry parameters such as "; charset=utf-8", so compare
	// only the media type.
	mediaType, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	if !strings.EqualFold(strings.TrimSpace(mediaType), "application/json") {
		return ErrUnsupportedMediaType
	}

	// MaxBytesReader also tells the server to stop reading an oversized body.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return decodeError(err)
	}

	// A well-formed request contains exactly one JSON value.
	if err := decoder.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return errors.New("Request body must contain exactly one JSON object.")
	}

	return nil
}

// decodeError rewrites encoding/json's messages, which leak Go type names, into
// something an API consumer can act on.
func decodeError(err error) error {
	var (
		syntaxErr        *json.SyntaxError
		unmarshalTypeErr *json.UnmarshalTypeError
		maxBytesErr      *http.MaxBytesError
	)

	switch {
	case errors.As(err, &syntaxErr):
		return fmt.Errorf("Request body contains malformed JSON at position %d.", syntaxErr.Offset)

	case errors.Is(err, io.ErrUnexpectedEOF):
		return errors.New("Request body contains malformed JSON.")

	case errors.As(err, &unmarshalTypeErr):
		return fmt.Errorf("Field %q must be of type %s.", unmarshalTypeErr.Field, unmarshalTypeErr.Type)

	case errors.Is(err, io.EOF):
		return errors.New("Request body must not be empty.")

	case errors.As(err, &maxBytesErr):
		return fmt.Errorf("Request body must not exceed %d bytes.", maxRequestBody)

	// DisallowUnknownFields has no typed error, so string matching is the
	// only option. Isolated here as the one place to update.
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		field := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)

		return fmt.Errorf("Unknown field %q.", field)

	default:
		return errors.New("Request body could not be parsed.")
	}
}
