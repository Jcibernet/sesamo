package user

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// fakeBcryptHash returns a string shaped like a bcrypt hash. ImportBatch
// stores password_hash verbatim without validating its format, so any
// unique string exercises the "stored as-is" contract.
func fakeBcryptHash(seed string) string {
	return "$2a$10$" + seed + ".fakehashfakehashfakeh"
}

func importRecord(email string, verified bool, hash string, name *string) ImportRecord {
	return ImportRecord{
		Email:         email,
		EmailVerified: verified,
		PasswordHash:  hash,
		Name:          name,
	}
}

// cleanupImportedEmails registers a t.Cleanup that deletes every row for
// the given emails, regardless of whether ImportBatch actually created
// them (a mixed-batch test may pre-seed one of them separately).
func cleanupImportedEmails(t *testing.T, pool *pgxpool.Pool, emails []string) {
	t.Helper()
	t.Cleanup(func() {
		if len(emails) == 0 {
			return
		}
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM users WHERE email = ANY($1)`, emails)
	})
}

func queryImportedUser(t *testing.T, pool *pgxpool.Pool, email string) (verified bool, hash string, name *string) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT email_verified, password_hash, name FROM users WHERE email = $1`, email).
		Scan(&verified, &hash, &name)
	if err != nil {
		t.Fatalf("query imported user %s: %v", email, err)
	}
	return verified, hash, name
}

// TestImportBatchCreatesNewUsers verifies a fresh batch of unique emails
// is inserted in full, with password_hash stored verbatim and
// email_verified round-tripping per record.
func TestImportBatchCreatesNewUsers(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	const n = 3
	emails := make([]string, n)
	names := make([]string, n)
	recs := make([]ImportRecord, n)
	for i := range n {
		emails[i] = "import-fresh-" + randSuffix() + "@test.local"
		names[i] = "Fresh User " + randSuffix()
		recs[i] = importRecord(emails[i], i%2 == 0, fakeBcryptHash(randSuffix()), &names[i])
	}
	cleanupImportedEmails(t, pool, emails)

	created, err := s.ImportBatch(ctx, recs)
	if err != nil {
		t.Fatalf("ImportBatch: %v", err)
	}
	if created != n {
		t.Fatalf("created = %d, want %d", created, n)
	}

	for i, rec := range recs {
		verified, hash, name := queryImportedUser(t, pool, emails[i])
		if hash != rec.PasswordHash {
			t.Fatalf("password_hash for %s = %q, want verbatim %q", emails[i], hash, rec.PasswordHash)
		}
		if verified != rec.EmailVerified {
			t.Fatalf("email_verified for %s = %v, want %v", emails[i], verified, rec.EmailVerified)
		}
		if name == nil || *name != names[i] {
			t.Fatalf("name for %s = %v, want %q", emails[i], name, names[i])
		}
	}
}

// TestImportBatchRerunIsIdempotent verifies re-importing the exact same
// batch skips every record (ON CONFLICT (email) DO NOTHING).
func TestImportBatchRerunIsIdempotent(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	emails := []string{
		"import-idem-" + randSuffix() + "@test.local",
		"import-idem-" + randSuffix() + "@test.local",
	}
	recs := []ImportRecord{
		importRecord(emails[0], true, fakeBcryptHash(randSuffix()), nil),
		importRecord(emails[1], false, fakeBcryptHash(randSuffix()), nil),
	}
	cleanupImportedEmails(t, pool, emails)

	created, err := s.ImportBatch(ctx, recs)
	if err != nil {
		t.Fatalf("first ImportBatch: %v", err)
	}
	if created != len(recs) {
		t.Fatalf("first run created = %d, want %d", created, len(recs))
	}

	created, err = s.ImportBatch(ctx, recs)
	if err != nil {
		t.Fatalf("second ImportBatch: %v", err)
	}
	if created != 0 {
		t.Fatalf("rerun created = %d, want 0 (every record already exists)", created)
	}
}

// TestImportBatchMixedSkipsExistingWithoutOverwrite verifies a batch
// mixing pre-existing and new emails only counts the new ones as
// created, and never mutates the already-stored row for an existing
// email (ON CONFLICT DO NOTHING, not DO UPDATE).
func TestImportBatchMixedSkipsExistingWithoutOverwrite(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	existingEmail := "import-mixed-existing-" + randSuffix() + "@test.local"
	newEmail := "import-mixed-new-" + randSuffix() + "@test.local"
	cleanupImportedEmails(t, pool, []string{existingEmail, newEmail})

	origName := "Original Name " + randSuffix()
	origHash := fakeBcryptHash("orig-" + randSuffix())
	seed := []ImportRecord{importRecord(existingEmail, true, origHash, &origName)}
	created, err := s.ImportBatch(ctx, seed)
	if err != nil {
		t.Fatalf("seed ImportBatch: %v", err)
	}
	if created != 1 {
		t.Fatalf("seed created = %d, want 1", created)
	}

	clashName := "Clashing Name " + randSuffix()
	newHash := fakeBcryptHash("new-" + randSuffix())
	mixed := []ImportRecord{
		// Same email as the seed row, but different verified flag, hash
		// and name: none of this must land if the row already exists.
		importRecord(existingEmail, false, fakeBcryptHash("clash-"+randSuffix()), &clashName),
		importRecord(newEmail, true, newHash, nil),
	}
	created, err = s.ImportBatch(ctx, mixed)
	if err != nil {
		t.Fatalf("mixed ImportBatch: %v", err)
	}
	if created != 1 {
		t.Fatalf("mixed created = %d, want 1 (only the new email)", created)
	}

	verified, hash, name := queryImportedUser(t, pool, existingEmail)
	if !verified {
		t.Fatalf("existing row's email_verified must not change: got %v want true", verified)
	}
	if hash != origHash {
		t.Fatalf("existing row's password_hash must not change: got %q want %q", hash, origHash)
	}
	if name == nil || *name != origName {
		t.Fatalf("existing row's name must not be overwritten: got %v want %q", name, origName)
	}

	newVerified, gotNewHash, _ := queryImportedUser(t, pool, newEmail)
	if !newVerified || gotNewHash != newHash {
		t.Fatalf("new row not inserted as given: verified=%v hash=%q", newVerified, gotNewHash)
	}
}

// TestImportBatchEmptyInputs verifies nil and zero-length slices are a
// documented no-op: no error, nothing created.
func TestImportBatchEmptyInputs(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	created, err := s.ImportBatch(ctx, nil)
	if err != nil {
		t.Fatalf("nil slice: unexpected error: %v", err)
	}
	if created != 0 {
		t.Fatalf("nil slice created = %d, want 0", created)
	}

	created, err = s.ImportBatch(ctx, []ImportRecord{})
	if err != nil {
		t.Fatalf("empty slice: unexpected error: %v", err)
	}
	if created != 0 {
		t.Fatalf("empty slice created = %d, want 0", created)
	}
}
