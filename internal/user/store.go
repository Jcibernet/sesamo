package user

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcibernet/sesamo/internal/crypto"
)

// Store provides user/identity data access.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore constructs a user Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// OAuthProfile is the normalized profile returned by a provider.
type OAuthProfile struct {
	Provider      string
	Sub           string
	Email         string
	EmailVerified bool
	Name          *string
	PictureURL    *string
}

// UpsertResult reports the resolved user id and whether it was created.
type UpsertResult struct {
	UserID string
	IsNew  bool
}

// UpsertByOAuth resolves a user from an OAuth profile. It links by
// (provider, provider_sub) first; if no identity exists it links to an
// existing user by email, or creates a new user. Returns whether the
// user account was newly created.
func (s *Store) UpsertByOAuth(ctx context.Context, p OAuthProfile) (UpsertResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return UpsertResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Existing identity?
	var userID string
	err = tx.QueryRow(ctx,
		`SELECT user_id FROM identities WHERE provider = $1 AND provider_sub = $2`,
		p.Provider, p.Sub).Scan(&userID)
	if err == nil {
		// Refresh mutable profile fields.
		if _, err := tx.Exec(ctx,
			`UPDATE users SET name = $2, picture_url = $3, updated_at = now() WHERE id = $1`,
			userID, p.Name, p.PictureURL); err != nil {
			return UpsertResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return UpsertResult{}, err
		}
		return UpsertResult{UserID: userID, IsNew: false}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return UpsertResult{}, err
	}

	// 2. Existing user by email? Link a new identity to it.
	isNew := false
	err = tx.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, p.Email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		// 3. Create a new user.
		userID = crypto.UUIDv7()
		if _, err := tx.Exec(ctx,
			`INSERT INTO users (id, email, email_verified, name, picture_url)
			 VALUES ($1, $2, $3, $4, $5)`,
			userID, p.Email, p.EmailVerified, p.Name, p.PictureURL); err != nil {
			return UpsertResult{}, err
		}
		isNew = true
	} else if err != nil {
		return UpsertResult{}, err
	}

	// Link the identity.
	if _, err := tx.Exec(ctx,
		`INSERT INTO identities (id, user_id, provider, provider_sub)
		 VALUES ($1, $2, $3, $4)`,
		crypto.UUIDv7(), userID, p.Provider, p.Sub); err != nil {
		return UpsertResult{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return UpsertResult{}, err
	}
	return UpsertResult{UserID: userID, IsNew: isNew}, nil
}

// ByID loads a user by id.
func (s *Store) ByID(ctx context.Context, id string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, email_verified, name, picture_url, created_at, metadata
		 FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Name, &u.PictureURL, &u.CreatedAt, &u.Metadata)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ByEmail loads a user by email. Returns (nil, nil) when not found.
func (s *Store) ByEmail(ctx context.Context, email string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, email_verified, name, picture_url, created_at, metadata
		 FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Name, &u.PictureURL, &u.CreatedAt, &u.Metadata)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}
