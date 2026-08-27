package user

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// executor is the subset of *pgxpool.Pool and pgx.Tx the store needs, so
// each statement lives exactly once and the pooled and transactional
// entry points cannot drift apart.
type executor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// CreateWithPassword creates a new user with an Argon2id password hash.
// Email uniqueness is enforced by the DB.
func (s *Store) CreateWithPassword(ctx context.Context, id, email, passwordHash string) error {
	return createWithPassword(ctx, s.pool, id, email, passwordHash)
}

// CreateWithPasswordTx is CreateWithPassword inside a caller-owned
// transaction, so the account and its evidence row land together.
func (s *Store) CreateWithPasswordTx(ctx context.Context, tx pgx.Tx, id, email, passwordHash string) error {
	return createWithPassword(ctx, tx, id, email, passwordHash)
}

func createWithPassword(ctx context.Context, ex executor, id, email, passwordHash string) error {
	_, err := ex.Exec(ctx,
		`INSERT INTO users (id, email, email_verified, password_hash)
		 VALUES ($1, $2, false, $3)`, id, email, passwordHash)
	return err
}

// Credential is the password-login lookup for one email address.
type Credential struct {
	UserID string
	Hash   string
	// HasPassword is false when the email matches no user or the account
	// is OAuth-only: either way there is nothing to verify.
	HasPassword bool
	// Disabled mirrors users.disabled. It is returned rather than folded
	// into HasPassword because the two need different audit reasons even
	// though the caller must answer identically to both.
	Disabled bool
}

// PasswordCredential returns the stored PHC hash for an email plus the
// account's disabled flag. A missing user yields the zero value.
func (s *Store) PasswordCredential(ctx context.Context, email string) (Credential, error) {
	var (
		c  Credential
		ph *string
	)
	err := s.pool.QueryRow(ctx,
		`SELECT id, password_hash, disabled FROM users WHERE email = $1`, email).
		Scan(&c.UserID, &ph, &c.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, nil
	}
	if err != nil {
		return Credential{}, err
	}
	if ph != nil {
		c.Hash, c.HasPassword = *ph, true
	}
	return c, nil
}

// SetPassword updates a user's password hash (used by reset + lazy
// re-hash after a successful bcrypt login).
func (s *Store) SetPassword(ctx context.Context, userID, passwordHash string) error {
	return setPassword(ctx, s.pool, userID, passwordHash)
}

// SetPasswordTx is SetPassword inside a caller-owned transaction.
func (s *Store) SetPasswordTx(ctx context.Context, tx pgx.Tx, userID, passwordHash string) error {
	return setPassword(ctx, tx, userID, passwordHash)
}

func setPassword(ctx context.Context, ex executor, userID, passwordHash string) error {
	_, err := ex.Exec(ctx,
		`UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`,
		userID, passwordHash)
	return err
}

// MarkEmailVerified flips email_verified to true.
func (s *Store) MarkEmailVerified(ctx context.Context, userID string) error {
	return markEmailVerified(ctx, s.pool, userID)
}

// MarkEmailVerifiedTx is MarkEmailVerified inside a caller-owned transaction.
func (s *Store) MarkEmailVerifiedTx(ctx context.Context, tx pgx.Tx, userID string) error {
	return markEmailVerified(ctx, tx, userID)
}

func markEmailVerified(ctx context.Context, ex executor, userID string) error {
	_, err := ex.Exec(ctx,
		`UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1`, userID)
	return err
}

// SetDisabled flips the account kill switch. Idempotent: setting the
// value it already has is a no-op write, so callers never have to read
// first.
func (s *Store) SetDisabled(ctx context.Context, userID string, disabled bool) error {
	return setDisabled(ctx, s.pool, userID, disabled)
}

// SetDisabledTx is SetDisabled inside a caller-owned transaction, so the
// flip, the session revocations it implies, and the evidence row land
// together.
func (s *Store) SetDisabledTx(ctx context.Context, tx pgx.Tx, userID string, disabled bool) error {
	return setDisabled(ctx, tx, userID, disabled)
}

func setDisabled(ctx context.Context, ex executor, userID string, disabled bool) error {
	_, err := ex.Exec(ctx,
		`UPDATE users SET disabled = $2, updated_at = now() WHERE id = $1`,
		userID, disabled)
	return err
}

// DisabledTx reports whether an account's kill switch is on, inside a
// caller-owned transaction. Flows that resolve a user from a one-time
// token need the check to share that token's transaction: refusing a
// disabled account must roll the spend back, not burn the link.
func (s *Store) DisabledTx(ctx context.Context, tx pgx.Tx, userID string) (bool, error) {
	var disabled bool
	err := tx.QueryRow(ctx, `SELECT disabled FROM users WHERE id = $1`, userID).Scan(&disabled)
	return disabled, err
}
