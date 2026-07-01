package http

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcibernet/sesamo/internal/email"
)

// testLogger discards output during tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// issueRawResetToken mints a real reset token (returning the raw value)
// so tests can exercise the /reset/confirm flow without scraping email.
func issueRawResetToken(pool *pgxpool.Pool, userID string) (string, error) {
	ts := email.NewTokenStore(pool)
	return ts.Issue(context.Background(), userID, email.PurposeReset, 15*time.Minute)
}
