package session

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcibernet/sesamo/internal/crypto"
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

// makeUser inserts a throwaway user and returns its id.
func makeUser(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	id := crypto.UUIDv7()
	email := id + "@test.local"
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, email, email_verified) VALUES ($1, $2, true)`, id, email)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

func newStore(pool *pgxpool.Pool) *Store {
	return NewStore(pool, Config{
		Lifetime:                30 * 24 * time.Hour,
		RollingRenewalThreshold: 15 * time.Minute,
	})
}

func TestCreateAndValidate(t *testing.T) {
	pool := testPool(t)
	s := newStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	created, err := s.Create(ctx, CreateInput{UserID: uid})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Validate(ctx, created.Token)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != KindValid {
		t.Fatalf("expected valid, got %v", res.Kind)
	}
	if res.User.ID != uid {
		t.Fatalf("user mismatch: %s != %s", res.User.ID, uid)
	}
}

func TestValidateNotFound(t *testing.T) {
	pool := testPool(t)
	s := newStore(pool)
	res, err := s.Validate(context.Background(), crypto.GenerateToken())
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != KindNotFound {
		t.Fatalf("expected not_found, got %v", res.Kind)
	}
}

func TestRevokeKillsSessionImmediately(t *testing.T) {
	pool := testPool(t)
	s := newStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	created, _ := s.Create(ctx, CreateInput{UserID: uid})
	gotUID, err := s.Revoke(ctx, created.Token)
	if err != nil {
		t.Fatal(err)
	}
	if gotUID != uid {
		t.Fatalf("Revoke should return the session's user id: got %q want %q", gotUID, uid)
	}
	res, _ := s.Validate(ctx, created.Token)
	if res.Kind != KindNotFound {
		t.Fatalf("revoked session should be not_found, got %v", res.Kind)
	}
}

func TestRotateChangesTokenAndInvalidatesOld(t *testing.T) {
	pool := testPool(t)
	s := newStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	first, _ := s.Create(ctx, CreateInput{UserID: uid})
	second, err := s.Rotate(ctx, first.Token, CreateInput{UserID: uid})
	if err != nil {
		t.Fatal(err)
	}
	if first.Token == second.Token {
		t.Fatal("rotate must produce a new token")
	}
	// Old token dead.
	if res, _ := s.Validate(ctx, first.Token); res.Kind != KindNotFound {
		t.Fatalf("old token should be dead, got %v", res.Kind)
	}
	// New token live.
	if res, _ := s.Validate(ctx, second.Token); res.Kind != KindValid {
		t.Fatalf("new token should be valid, got %v", res.Kind)
	}
}

func TestExpiredSessionRejectedAndDeleted(t *testing.T) {
	pool := testPool(t)
	uid := makeUser(t, pool)
	ctx := context.Background()

	// Store with negative lifetime so the session is born expired.
	s := NewStore(pool, Config{Lifetime: -1 * time.Hour, RollingRenewalThreshold: 15 * time.Minute})
	created, _ := s.Create(ctx, CreateInput{UserID: uid})
	res, _ := s.Validate(ctx, created.Token)
	if res.Kind != KindExpired {
		t.Fatalf("expected expired, got %v", res.Kind)
	}
	// Second validate => deleted, so not_found.
	res, _ = s.Validate(ctx, created.Token)
	if res.Kind != KindNotFound {
		t.Fatalf("expired session should be purged, got %v", res.Kind)
	}
}

func TestRollingRenewalExtendsExpiry(t *testing.T) {
	pool := testPool(t)
	uid := makeUser(t, pool)
	ctx := context.Background()

	// Zero threshold => every validate renews.
	s := NewStore(pool, Config{Lifetime: 24 * time.Hour, RollingRenewalThreshold: 0})
	created, _ := s.Create(ctx, CreateInput{UserID: uid})
	time.Sleep(10 * time.Millisecond)
	res, err := s.Validate(ctx, created.Token)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Renewed {
		t.Fatal("expected rolling renewal to fire")
	}
	if !res.ExpiresAt.After(created.ExpiresAt) {
		t.Fatalf("expiry not extended: %v <= %v", res.ExpiresAt, created.ExpiresAt)
	}
}

func TestPurgeExpiredDeletesExpiredSessions(t *testing.T) {
	pool := testPool(t)
	s := newStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	created, err := s.Create(ctx, CreateInput{UserID: uid})
	if err != nil {
		t.Fatal(err)
	}

	// Force the session into the past so PurgeExpired has something to
	// reap, without waiting out its real lifetime.
	if _, err := pool.Exec(ctx,
		`UPDATE sessions SET expires_at = now() - interval '1 hour' WHERE user_id = $1`, uid); err != nil {
		t.Fatalf("force-expire: %v", err)
	}

	n, err := s.PurgeExpired(ctx)
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if n < 1 {
		t.Fatalf("PurgeExpired count = %d, want >= 1", n)
	}

	res, err := s.Validate(ctx, created.Token)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind == KindValid {
		t.Fatal("purged session should no longer validate")
	}
}
