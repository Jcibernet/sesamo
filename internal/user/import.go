package user

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/jcibernet/sesamo/internal/crypto"
)

// ImportRecord is one account from an external export (e.g. Auth0).
type ImportRecord struct {
	Email         string
	EmailVerified bool
	PasswordHash  string // existing bcrypt hash, stored as-is
	Name          *string
}

// ImportOutcome reports what happened to a single imported record.
type ImportOutcome int

const (
	// ImportCreated: a new user row was inserted.
	ImportCreated ImportOutcome = iota
	// ImportSkipped: a user with this email already existed.
	ImportSkipped
)

// Import inserts a user with a pre-existing password hash (bcrypt from
// Auth0). The hash is stored verbatim so the user's existing password
// keeps working; it is lazily re-hashed to Argon2id on first login. If
// the email already exists the record is skipped (idempotent re-runs).
func (s *Store) Import(ctx context.Context, rec ImportRecord) (ImportOutcome, error) {
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO users (id, email, email_verified, password_hash, name)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (email) DO NOTHING`,
		crypto.UUIDv7(), rec.Email, rec.EmailVerified, rec.PasswordHash, rec.Name)
	if err != nil {
		return ImportSkipped, err
	}
	if tag.RowsAffected() == 0 {
		return ImportSkipped, nil
	}
	return ImportCreated, nil
}

// ImportBatch inserts many records in a single pipelined round trip
// (pgx.Batch): the dominant cost of a bulk import against a remote
// Postgres is per-row RTT, and this collapses len(recs) round trips
// into one. Semantics match Import (ON CONFLICT (email) DO NOTHING).
// The batch runs in one implicit transaction, so on error nothing from
// this batch is committed; the caller should fall back to row-by-row
// Import to isolate the bad record. Returns the number created;
// skipped = len(recs) - created.
func (s *Store) ImportBatch(ctx context.Context, recs []ImportRecord) (created int, err error) {
	b := &pgx.Batch{}
	for _, rec := range recs {
		b.Queue(
			`INSERT INTO users (id, email, email_verified, password_hash, name)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (email) DO NOTHING`,
			crypto.UUIDv7(), rec.Email, rec.EmailVerified, rec.PasswordHash, rec.Name)
	}
	br := s.pool.SendBatch(ctx, b)
	defer br.Close()
	for range recs {
		tag, err := br.Exec()
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() > 0 {
			created++
		}
	}
	if err := br.Close(); err != nil {
		return 0, err
	}
	return created, nil
}
