// Command api is the entrypoint for the Aven HTTP API.
//
// It is the only place that reads the environment or decides an exit code;
// everything below receives what it needs as a parameter, which is what keeps
// the rest testable.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/rithvik/aven/server/internal/auth"
	"github.com/rithvik/aven/server/internal/database"
	"github.com/rithvik/aven/server/internal/httpx"
	"github.com/rithvik/aven/server/internal/post"
	"github.com/rithvik/aven/server/internal/user"
)

func main() {
	// All real work happens in run so deferred cleanup still executes;
	// os.Exit would skip it.
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	addr := env("SERVER_ADDR", ":8080")
	dbPath := env("DATABASE_PATH", "./data/aven.db")

	// The signing secret has no default. A fallback here would be a fallback
	// in production too, and a well-known signing key means anyone can mint
	// a token for any account.
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return errors.New("JWT_SECRET must be set")
	}

	// Secure cookies are the default and must be turned off explicitly. The
	// mistake this ordering prevents is shipping with the flag unset and
	// silently sending the refresh token over plaintext.
	secureCookies := env("COOKIE_SECURE", "true") != "false"
	if !secureCookies {
		logger.Warn("cookie Secure flag is disabled; use only for local http development")
	}

	loginLimiter, err := newAuthLimiter("LOGIN", 10, time.Minute)
	if err != nil {
		return err
	}
	refreshLimiter, err := newAuthLimiter("REFRESH", 30, time.Minute)
	if err != nil {
		return err
	}

	// signal.NotifyContext turns SIGINT and SIGTERM into a cancelled context,
	// so shutdown uses the same mechanism as every other deadline.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	users := user.NewStore(db)
	tokens := auth.NewStore(db)
	posts := post.NewStore(db)

	authService, err := auth.NewService(users, tokens, auth.Config{
		Secret:          []byte(secret),
		Issuer:          env("JWT_ISSUER", "aven"),
		AccessTokenTTL:  auth.DefaultAccessTokenTTL,
		RefreshTokenTTL: auth.DefaultRefreshTokenTTL,
	})
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	user.NewHandler(users, logger).Register(mux)
	auth.NewHandler(authService, logger, secureCookies, loginLimiter, refreshLimiter).Register(mux)
	post.NewHandler(posts, authService.Issuer(), logger).Register(mux)

	// Expired tokens authenticate nothing, but they accumulate: one row per
	// refresh, per user, forever. Sweeping them keeps the table and its
	// indexes proportional to live sessions rather than to total history.
	go sweepExpiredTokens(ctx, tokens, logger)

	srv := &http.Server{
		Addr:    addr,
		Handler: withRecovery(withLogging(mux, logger), logger),

		// Without timeouts a slow client can hold a connection open
		// indefinitely and exhaust the server's file descriptors.
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Buffered so the goroutine can always exit, even if shutdown wins the
	// race and nothing reads the channel.
	serveErr := make(chan error, 1)

	go func() {
		logger.Info("listening", "addr", addr, "database", dbPath)

		// ErrServerClosed is the expected result of Shutdown, not a fault.
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err

			return
		}

		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err

	case <-ctx.Done():
		logger.Info("shutting down")

		// A fresh context: the one that triggered shutdown is already
		// cancelled, so reusing it would cut off in-flight requests
		// instead of letting them finish.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		return srv.Shutdown(shutdownCtx)
	}
}

// tokenSweepInterval is how often expired refresh tokens are deleted. The rows
// are already unusable by then, so this is housekeeping and nothing is gained
// by running it more often.
const tokenSweepInterval = time.Hour

// sweepExpiredTokens deletes expired refresh tokens until ctx is cancelled.
//
// A failure here is logged and retried on the next tick rather than returned: a
// full disk or a locked database should not take the API down when the only
// consequence of skipping a sweep is a slightly larger table.
func sweepExpiredTokens(ctx context.Context, tokens *auth.Store, logger *slog.Logger) {
	ticker := time.NewTicker(tokenSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			// A bounded context of its own: ctx lives for the
			// process, so a wedged delete would otherwise hang here
			// until shutdown.
			sweepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			removed, err := tokens.DeleteExpired(sweepCtx, time.Now().UTC())
			cancel()

			if err != nil {
				logger.ErrorContext(ctx, "failed to sweep expired refresh tokens",
					slog.String("error", err.Error()))

				continue
			}

			if removed > 0 {
				logger.InfoContext(ctx, "swept expired refresh tokens",
					slog.Int64("removed", removed))
			}
		}
	}
}

// health reports that the process is running. It touches no dependency: a
// liveness probe that checks the database gets the whole fleet restarted during
// a database blip, turning a recoverable outage into an unrecoverable one.
func health(w http.ResponseWriter, _ *http.Request) {
	httpx.Encode(w, http.StatusOK, map[string]string{"status": "ok"})
}

// withRecovery turns a panic into a 500.
//
// Without it net/http logs the panic and drops the connection, leaving the
// client with a transport error rather than a response. The stack trace goes to
// the logs; the client sees only a generic message.
func withRecovery(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}

			// net/http panics with this sentinel when a handler aborts a
			// broken connection. The connection is gone, so let the
			// server tear it down as it normally would.
			if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(recovered)
			}

			logger.ErrorContext(r.Context(), "recovered from panic",
				"panic", recovered,
				"stack", string(debug.Stack()),
			)

			httpx.Error(w, http.StatusInternalServerError, "internal_error",
				"An unexpected error occurred.")
		}()

		next.ServeHTTP(w, r)
	})
}

// withLogging emits one structured record per request.
//
// Severity follows the status, so an alert on error-level logs fires for server
// faults rather than for a client's typo.
func withLogging(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(recorder, r)

		logger.LogAttrs(r.Context(), levelFor(recorder.status), "request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", recorder.status),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		)
	})
}

// statusRecorder captures the status code, which http.ResponseWriter gives no
// way to read back.
//
// It implements Unwrap rather than re-declaring Flush and Hijack: since Go 1.20
// http.ResponseController reaches optional capabilities by walking the Unwrap
// chain, so nothing is lost by keeping this small.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func levelFor(status int) slog.Level {
	switch {
	case status >= http.StatusInternalServerError:
		return slog.LevelError
	case status >= http.StatusBadRequest:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// env returns the value of key, or fallback when unset or empty.
func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}

func newAuthLimiter(prefix string, defaultCapacity int, defaultRefill time.Duration) (*auth.Limiter, error) {
	capacity := defaultCapacity
	if value := os.Getenv(prefix + "_RATE_LIMIT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return nil, errors.New(prefix + "_RATE_LIMIT must be an integer")
		}
		capacity = parsed
	}

	refill := defaultRefill
	if value := os.Getenv(prefix + "_RATE_WINDOW"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return nil, errors.New(prefix + "_RATE_WINDOW must be a duration")
		}
		refill = parsed
	}

	return auth.NewLimiter(auth.LimiterConfig{Capacity: capacity, RefillRate: refill})
}
