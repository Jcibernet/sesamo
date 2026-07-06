package email

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcibernet/sesamo/internal/crypto"
)

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

func makeUser(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	id := crypto.UUIDv7()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, email, email_verified) VALUES ($1, $2, false)`,
		id, id+"@test.local")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

func TestTokenSingleUse(t *testing.T) {
	pool := testPool(t)
	ts := NewTokenStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	tok, err := ts.Issue(ctx, uid, PurposeReset, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ts.Consume(ctx, tok, PurposeReset)
	if err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if got != uid {
		t.Fatalf("user mismatch: %s != %s", got, uid)
	}
	// Second consume must fail (single-use).
	if _, err := ts.Consume(ctx, tok, PurposeReset); err == nil {
		t.Fatal("token reuse should fail")
	}
}

func TestTokenWrongPurposeRejected(t *testing.T) {
	pool := testPool(t)
	ts := NewTokenStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	tok, _ := ts.Issue(ctx, uid, PurposeVerify, 15*time.Minute)
	if _, err := ts.Consume(ctx, tok, PurposeReset); err == nil {
		t.Fatal("token must not be consumable under a different purpose")
	}
}

func TestTokenExpired(t *testing.T) {
	pool := testPool(t)
	ts := NewTokenStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	tok, _ := ts.Issue(ctx, uid, PurposeMagicLink, -1*time.Minute) // already expired
	if _, err := ts.Consume(ctx, tok, PurposeMagicLink); err == nil {
		t.Fatal("expired token should fail")
	}
}

func TestIssueInvalidatesPriorToken(t *testing.T) {
	pool := testPool(t)
	ts := NewTokenStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	first, _ := ts.Issue(ctx, uid, PurposeReset, 15*time.Minute)
	_, _ = ts.Issue(ctx, uid, PurposeReset, 15*time.Minute) // supersedes first
	if _, err := ts.Consume(ctx, first, PurposeReset); err == nil {
		t.Fatal("older token should be invalidated when a new one is issued")
	}
}

func TestPurgeExpiredRemovesConsumedAndExpiredTokens(t *testing.T) {
	pool := testPool(t)
	ts := NewTokenStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	consumed, err := ts.Issue(ctx, uid, PurposeReset, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Consume(ctx, consumed, PurposeReset); err != nil {
		t.Fatalf("consume: %v", err)
	}

	if _, err := ts.Issue(ctx, uid, PurposeVerify, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE one_time_tokens SET expires_at = now() - interval '1 hour' WHERE user_id = $1 AND purpose = $2`,
		uid, PurposeVerify); err != nil {
		t.Fatalf("force-expire: %v", err)
	}

	n, err := ts.PurgeExpired(ctx)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n < 2 {
		t.Fatalf("PurgeExpired count = %d, want >= 2", n)
	}

	var remaining int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM one_time_tokens WHERE user_id = $1`, uid).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected all tokens for user purged, %d remain", remaining)
	}
}
