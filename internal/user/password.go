package user

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// CreateWithPassword creates a new user with an Argon2id password hash.
// Returns the new user id. Email uniqueness is enforced by the DB.
func (s *Store) CreateWithPassword(ctx context.Context, id, email, passwordHash string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (id, email, email_verified, password_hash)
		 VALUES ($1, $2, false, $3)`, id, email, passwordHash)
	return err
}

// PasswordHash returns the stored PHC hash for an email, or ("", false)
// if the user does not exist or has no password set.
func (s *Store) PasswordHash(ctx context.Context, email string) (id string, hash string, ok bool, err error) {
	var ph *string
	err = s.pool.QueryRow(ctx,
		`SELECT id, password_hash FROM users WHERE email = $1`, email).Scan(&id, &ph)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	if ph == nil {
		return id, "", false, nil
	}
	return id, *ph, true, nil
}

// SetPassword updates a user's password hash (used by reset + lazy
// re-hash after a successful bcrypt login).
func (s *Store) SetPassword(ctx context.Context, userID, passwordHash string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`,
		userID, passwordHash)
	return err
}

// MarkEmailVerified flips email_verified to true.
func (s *Store) MarkEmailVerified(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1`, userID)
	return err
}
