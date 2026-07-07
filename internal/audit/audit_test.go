package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
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

// testPool connects to the dev DB. Tests are skipped if SESAMO_TEST_DB
// is not set, so `go test ./...` stays green without infra.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SESAMO_TEST_DB")
	if dsn == "" {
		t.Skip("SESAMO_TEST_DB not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// randMarker returns a value unique to this invocation so audit rows
// created by concurrent or repeated test runs never collide, and this
// test only ever touches the rows it created.
func randMarker(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b[:])
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

// TestPurgeOlderThanRespectsRetention verifies the retention contract:
// rows backdated past the retention window are deleted, rows inside
// the window survive, and the reported count covers at least the rows
// this test backdated. Other rows in the shared table may also be
// older than the window and get purged alongside them, so the test
// never asserts exact equality against the global table — only that
// its own marked rows behave correctly.
func TestPurgeOlderThanRespectsRetention(t *testing.T) {
	pool := testPool(t)
	l := New(pool, discardLogger(), false)
	ctx := context.Background()

	marker := randMarker(t)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM audit_log WHERE detail->>'marker' = $1`, marker)
	})

	const backdatedCount = 3
	const freshCount = 2

	for i := range backdatedCount {
		if err := l.Record(ctx, LoginFailed, "", "127.0.0.1", map[string]any{
			"marker": marker, "kind": "backdated",
		}); err != nil {
			t.Fatalf("Record (backdated seed %d): %v", i, err)
		}
	}
	for i := range freshCount {
		if err := l.Record(ctx, LoginFailed, "", "127.0.0.1", map[string]any{
			"marker": marker, "kind": "fresh",
		}); err != nil {
			t.Fatalf("Record (fresh seed %d): %v", i, err)
		}
	}

	if _, err := pool.Exec(ctx, `
		UPDATE audit_log SET occurred_at = now() - interval '10 days'
		 WHERE detail->>'marker' = $1 AND detail->>'kind' = 'backdated'`,
		marker); err != nil {
		t.Fatalf("backdate seed rows: %v", err)
	}

	purged, err := l.PurgeOlderThan(ctx, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("PurgeOlderThan: %v", err)
	}
	if purged < backdatedCount {
		t.Fatalf("PurgeOlderThan reported %d rows removed, want >= %d (this test's backdated rows)",
			purged, backdatedCount)
	}

	var remainingBackdated int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_log
		 WHERE detail->>'marker' = $1 AND detail->>'kind' = 'backdated'`,
		marker).Scan(&remainingBackdated); err != nil {
		t.Fatalf("count remaining backdated rows: %v", err)
	}
	if remainingBackdated != 0 {
		t.Fatalf("expected all backdated rows purged, %d remain", remainingBackdated)
	}

	var remainingFresh int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_log
		 WHERE detail->>'marker' = $1 AND detail->>'kind' = 'fresh'`,
		marker).Scan(&remainingFresh); err != nil {
		t.Fatalf("count remaining fresh rows: %v", err)
	}
	if remainingFresh != freshCount {
		t.Fatalf("expected %d fresh rows to survive purge, found %d", freshCount, remainingFresh)
	}
}
