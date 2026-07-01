package user

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
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

func TestUpsertCreatesThenLinks(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	name := "Test User"
	email := "upsert-" + randSuffix() + "@test.local"
	prof := OAuthProfile{
		Provider: "google", Sub: "sub-" + randSuffix(),
		Email: email, EmailVerified: true, Name: &name,
	}

	r1, err := s.UpsertByOAuth(ctx, prof)
	if err != nil {
		t.Fatal(err)
	}
	if !r1.IsNew {
		t.Fatal("first upsert should be new")
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, r1.UserID)
	})

	// Same identity again => existing.
	r2, err := s.UpsertByOAuth(ctx, prof)
	if err != nil {
		t.Fatal(err)
	}
	if r2.IsNew || r2.UserID != r1.UserID {
		t.Fatalf("second upsert should resolve same user: %+v", r2)
	}
}

func TestUpsertDifferentProviderSameEmailLinks(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	email := "link-" + randSuffix() + "@test.local"
	g := OAuthProfile{Provider: "google", Sub: "g-" + randSuffix(), Email: email, EmailVerified: true}
	r1, err := s.UpsertByOAuth(ctx, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, r1.UserID)
	})

	gh := OAuthProfile{Provider: "github", Sub: "gh-" + randSuffix(), Email: email, EmailVerified: true}
	r2, err := s.UpsertByOAuth(ctx, gh)
	if err != nil {
		t.Fatal(err)
	}
	if r2.IsNew {
		t.Fatal("second provider with same email should link, not create")
	}
	if r2.UserID != r1.UserID {
		t.Fatalf("same email should resolve same user: %s != %s", r2.UserID, r1.UserID)
	}
}
