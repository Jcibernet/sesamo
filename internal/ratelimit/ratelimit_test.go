package ratelimit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

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

// randomKey returns a bucket key unique to this test run so concurrent
// or repeated invocations never share state.
func randomKey(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return fmt.Sprintf("test:ratelimit:%s", hex.EncodeToString(b[:]))
}

// deleteBucket removes the row for key, ignoring "no such row".
func deleteBucket(t *testing.T, pool *pgxpool.Pool, key string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM rate_limit_buckets WHERE key = $1`, key); err != nil {
		t.Fatalf("cleanup bucket %q: %v", key, err)
	}
}

// TestAllowConcurrentNoOversubscribe defends the core invariant of the
// token bucket: a bucket with capacity C admits AT MOST C requests no
// matter how many callers race for it. Before the fix, the refill
// upsert and the token decrement ran as two separate implicit
// transactions, so concurrent callers could all observe the
// pre-decrement balance and oversubscribe the bucket, driving tokens
// negative. The fix wraps both statements in one transaction so the
// upsert's row lock serializes consumers.
func TestAllowConcurrentNoOversubscribe(t *testing.T) {
	pool := testPool(t)
	key := randomKey(t)
	t.Cleanup(func() { deleteBucket(t, pool, key) })

	limiter := New(pool)
	rule := Rule{Capacity: 10, RefillPerSec: 0.001}

	const goroutines = 50
	var (
		admitted int64
		wg       sync.WaitGroup
	)
	start := make(chan struct{})

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			allowed, _, err := limiter.Allow(context.Background(), key, rule)
			if err != nil {
				t.Errorf("Allow: %v", err)
				return
			}
			if allowed {
				atomic.AddInt64(&admitted, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&admitted); got != int64(rule.Capacity) {
		t.Fatalf("admitted %d requests, want exactly %d (capacity)", got, int64(rule.Capacity))
	}

	var tokens float64
	if err := pool.QueryRow(context.Background(),
		`SELECT tokens FROM rate_limit_buckets WHERE key = $1`, key).Scan(&tokens); err != nil {
		t.Fatalf("query tokens: %v", err)
	}
	if tokens < 0 {
		t.Fatalf("bucket tokens went negative: %v", tokens)
	}
}

// TestAllowDeniedReportsPositiveRetryAfter checks that once a bucket is
// exhausted, Allow reports a positive wait duration instead of 0 or a
// negative value.
func TestAllowDeniedReportsPositiveRetryAfter(t *testing.T) {
	pool := testPool(t)
	key := randomKey(t)
	t.Cleanup(func() { deleteBucket(t, pool, key) })

	limiter := New(pool)
	rule := Rule{Capacity: 1, RefillPerSec: 0.001}
	ctx := context.Background()

	allowed, _, err := limiter.Allow(ctx, key, rule)
	if err != nil {
		t.Fatalf("Allow (first): %v", err)
	}
	if !allowed {
		t.Fatalf("first call should be admitted (bucket starts full)")
	}

	allowed, retryAfter, err := limiter.Allow(ctx, key, rule)
	if err != nil {
		t.Fatalf("Allow (second): %v", err)
	}
	if allowed {
		t.Fatalf("second call should be denied (capacity exhausted)")
	}
	if retryAfter <= 0 {
		t.Fatalf("retryAfter = %v, want > 0", retryAfter)
	}
}

// TestPurgeStaleDeletesOldBucketsOnly defends the purge job: buckets
// untouched for longer than the retention window are reaped, but
// buckets that saw recent activity are left alone.
func TestPurgeStaleDeletesOldBucketsOnly(t *testing.T) {
	pool := testPool(t)
	staleKey := randomKey(t)
	freshKey := randomKey(t)
	t.Cleanup(func() { deleteBucket(t, pool, staleKey) })
	t.Cleanup(func() { deleteBucket(t, pool, freshKey) })
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`INSERT INTO rate_limit_buckets (key, tokens, updated_at) VALUES ($1, $2, now() - interval '2 days')`,
		staleKey, 5.0); err != nil {
		t.Fatalf("insert stale bucket: %v", err)
	}

	limiter := New(pool)
	if _, _, err := limiter.Allow(ctx, freshKey, Rule{Capacity: 5, RefillPerSec: 1}); err != nil {
		t.Fatalf("Allow (fresh): %v", err)
	}

	n, err := limiter.PurgeStale(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("PurgeStale: %v", err)
	}
	if n < 1 {
		t.Fatalf("PurgeStale count = %d, want >= 1", n)
	}

	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT exists(SELECT 1 FROM rate_limit_buckets WHERE key = $1)`, staleKey).Scan(&exists); err != nil {
		t.Fatalf("check stale: %v", err)
	}
	if exists {
		t.Fatal("stale bucket should have been purged")
	}

	if err := pool.QueryRow(ctx,
		`SELECT exists(SELECT 1 FROM rate_limit_buckets WHERE key = $1)`, freshKey).Scan(&exists); err != nil {
		t.Fatalf("check fresh: %v", err)
	}
	if !exists {
		t.Fatal("fresh bucket should have survived the purge")
	}
}
