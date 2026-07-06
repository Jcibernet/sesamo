package audit

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// unreachablePool builds a pool whose DSN parses successfully but whose
// connections always fail fast (connection refused) — no SESAMO_TEST_DB
// and no real database involved. pgxpool.New never dials eagerly, so
// construction always succeeds; the failure surfaces on the first Exec,
// bounded by connect_timeout=1.
func unreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(),
		"postgres://nobody:nope@127.0.0.1:1/void?connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New (DSN should parse without dialing): %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRecordBestEffortSwallowsWriteFailure verifies the default tradeoff:
// availability of the auth path wins over audit completeness. A
// guaranteed write failure (unreachable database) must never surface to
// the caller.
func TestRecordBestEffortSwallowsWriteFailure(t *testing.T) {
	pool := unreachablePool(t)
	l := New(pool, discardLogger(), false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err := l.Record(ctx, LoginSuccess, "", "127.0.0.1", nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("best-effort Record must swallow write failures, got: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Record took too long to fail fast on an unreachable DSN: %v", elapsed)
	}
}

// TestRecordStrictSurfacesWriteFailure verifies the SESAMO_AUDIT_STRICT
// tradeoff: a write failure must surface to the caller so the handler can
// abort the operation it was about to evidence.
func TestRecordStrictSurfacesWriteFailure(t *testing.T) {
	pool := unreachablePool(t)
	l := New(pool, discardLogger(), true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err := l.Record(ctx, LoginSuccess, "", "127.0.0.1", nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("strict Record must surface write failures, got nil error")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Record took too long to fail on an unreachable DSN: %v", elapsed)
	}
}
