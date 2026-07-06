// Package session implements the opaque-session lifecycle: create,
// validate (with rolling renewal), rotate (on privilege change), and
// revoke. The raw token is returned only to be placed in a cookie; the
// database stores SHA-256(token) as the primary key.
package session

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcibernet/sesamo/internal/crypto"
	"github.com/jcibernet/sesamo/internal/user"
)

// Config controls session lifetime and rolling renewal cadence.
type Config struct {
	Lifetime                time.Duration
	RollingRenewalThreshold time.Duration
}

// Kind enumerates validation outcomes.
type Kind int

const (
	// KindNotFound: token does not resolve to any session.
	KindNotFound Kind = iota
	// KindExpired: session existed but is past expiry (and was deleted).
	KindExpired
	// KindValid: session is live; User is populated.
	KindValid
)

// Result is the outcome of Validate.
type Result struct {
	Kind      Kind
	User      *user.User
	ExpiresAt time.Time
	// Renewed is true when rolling renewal extended the session and the
	// caller should re-emit the cookie with the new ExpiresAt.
	Renewed bool
}

// Store performs session operations against Postgres.
type Store struct {
	pool *pgxpool.Pool
	cfg  Config
}

// NewStore constructs a session Store.
func NewStore(pool *pgxpool.Pool, cfg Config) *Store {
	return &Store{pool: pool, cfg: cfg}
}

// CreateInput carries the per-session metadata captured at creation.
type CreateInput struct {
	UserID    string
	UserAgent *string
	IPFirst   *string
}

// Created is the result of Create: the raw token (for the cookie) and
// its absolute expiry.
type Created struct {
	Token     string
	ExpiresAt time.Time
}

// Create inserts a new session and returns the raw token. The raw token
// is never persisted; only its SHA-256 hash is stored.
func (s *Store) Create(ctx context.Context, in CreateInput) (Created, error) {
	token := crypto.GenerateToken()
	idHash := crypto.HashToken(token)
	now := time.Now().UTC()
	expiresAt := now.Add(s.cfg.Lifetime)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions
			(id_hash, user_id, created_at, last_used_at, expires_at, user_agent, ip_first)
		VALUES ($1, $2, $3, $3, $4, $5, $6)`,
		idHash, in.UserID, now, expiresAt, in.UserAgent, in.IPFirst)
	if err != nil {
		return Created{}, err
	}
	return Created{Token: token, ExpiresAt: expiresAt}, nil
}

// Validate looks up a session by raw token. On a live session past the
// rolling threshold it extends last_used_at + expires_at (one write per
// threshold window, not per request). Expired sessions are deleted
// opportunistically.
func (s *Store) Validate(ctx context.Context, token string) (Result, error) {
	idHash := crypto.HashToken(token)

	var (
		userID    string
		expiresAt time.Time
		lastUsed  time.Time
		u         user.User
		name      *string
		picture   *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT s.user_id, s.expires_at, s.last_used_at,
		       u.id, u.email, u.email_verified, u.name, u.picture_url,
		       u.created_at, u.metadata
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.id_hash = $1`, idHash).
		Scan(&userID, &expiresAt, &lastUsed,
			&u.ID, &u.Email, &u.EmailVerified, &name, &picture,
			&u.CreatedAt, &u.Metadata)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{Kind: KindNotFound}, nil
		}
		return Result{}, err
	}
	u.Name = name
	u.PictureURL = picture

	now := time.Now().UTC()
	if !expiresAt.After(now) {
		_, _ = s.pool.Exec(ctx, `DELETE FROM sessions WHERE id_hash = $1`, idHash)
		return Result{Kind: KindExpired}, nil
	}

	renewed := false
	if now.Sub(lastUsed) >= s.cfg.RollingRenewalThreshold {
		newExpiry := now.Add(s.cfg.Lifetime)
		_, err := s.pool.Exec(ctx, `
			UPDATE sessions SET last_used_at = $2, expires_at = $3
			WHERE id_hash = $1`, idHash, now, newExpiry)
		if err != nil {
			return Result{}, err
		}
		expiresAt = newExpiry
		renewed = true
	}

	return Result{Kind: KindValid, User: &u, ExpiresAt: expiresAt, Renewed: renewed}, nil
}

// Rotate invalidates the old token and issues a fresh session for the
// same user, preserving metadata. Call this on privilege change (login,
// role change, MFA step-up) to defend against session fixation.
func (s *Store) Rotate(ctx context.Context, oldToken string, in CreateInput) (Created, error) {
	if _, err := s.Revoke(ctx, oldToken); err != nil {
		return Created{}, err
	}
	return s.Create(ctx, in)
}

// Revoke deletes a single session by raw token and returns the user id
// it belonged to ("" when the token matched nothing). Idempotent.
func (s *Store) Revoke(ctx context.Context, token string) (string, error) {
	idHash := crypto.HashToken(token)
	var userID string
	err := s.pool.QueryRow(ctx,
		`DELETE FROM sessions WHERE id_hash = $1 RETURNING user_id`, idHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return userID, err
}

// RevokeAllForUser deletes every session for a user ("log out everywhere").
func (s *Store) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

// PurgeExpired deletes expired sessions and returns the count removed.
// Intended to be called from a periodic job.
func (s *Store) PurgeExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
