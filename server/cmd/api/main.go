// Command api is the entrypoint for the Aven HTTP API.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rithvik/aven/server/internal/api"
	"github.com/rithvik/aven/server/internal/database"
)

func main() {
	// All the real work happens in run so that deferred cleanup still runs;
	// os.Exit would skip it.
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	addr := env("SERVER_ADDR", ":8080")
	dbPath := env("DATABASE_PATH", "./data/aven.db")

	// Turns SIGINT/SIGTERM into a cancelled context, so shutdown uses the
	// same mechanism as every other deadline in the program.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	srv := &http.Server{
		Addr:    addr,
		Handler: api.New(db, logger).Routes(),

		// Without timeouts a slow client can hold a connection open
		// forever and exhaust the server's file descriptors.
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Buffered so this goroutine can always exit, even when shutdown wins
	// the race and nothing reads the channel.
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
		// cancelled, so reusing it would abort in-flight requests
		// instead of letting them finish.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		return srv.Shutdown(shutdownCtx)
	}
}

// env returns the value of key, or fallback when it is unset or empty.
func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}
