package http

import (
	"context"
	"io"
	"log/slog"
	"testing"
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

// issueRawMagicLinkToken mints a real magic-link token (returning the
// raw value) so tests can exercise /magiclink/confirm without email.
func issueRawMagicLinkToken(pool *pgxpool.Pool, userID string) (string, error) {
	ts := email.NewTokenStore(pool)
	return ts.Issue(context.Background(), userID, email.PurposeMagicLink, 15*time.Minute)
}

// resetRateLimits clears rate-limit buckets accumulated by prior test
// runs. All httptest traffic originates from 127.0.0.1 and every test
// identity lives under @test.local, so consecutive `go test` runs within
// the refill window would otherwise trip 429s and fail spuriously.
func resetRateLimits(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`DELETE FROM rate_limit_buckets
		  WHERE key = 'login_ip:127.0.0.1' OR key LIKE 'login_id:%@test.local'`)
	if err != nil {
		t.Fatalf("reset rate limits: %v", err)
	}
}
