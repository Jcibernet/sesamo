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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcibernet/sesamo/internal/crypto"
	"github.com/jcibernet/sesamo/internal/user"
)

// Config controls session lifetime and rolling renewal cadence.
type Config struct {
	Lifetime                time.Duration
	RollingRenewalThreshold time.Duration
	// MaxLifetime is the absolute cap on a session's life, measured from
	// its creation: rolling renewal can never push expires_at past
	// created_at+MaxLifetime, so a stolen-and-kept-warm cookie still
	// dies. Zero disables the cap (renew forever), the historical
	// behavior.
	MaxLifetime time.Duration
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

// executor is the subset of *pgxpool.Pool and pgx.Tx the store needs, so
// each statement lives exactly once and the pooled and transactional
// entry points cannot drift apart.
type executor interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Create inserts a new session and returns the raw token. The raw token
// is never persisted; only its SHA-256 hash is stored.
func (s *Store) Create(ctx context.Context, in CreateInput) (Created, error) {
	return s.create(ctx, s.pool, in)
}

// CreateTx is Create inside a caller-owned transaction: the session row
// commits — or rolls back — together with everything else the caller
// does in tx (in strict audit mode, the evidence row).
func (s *Store) CreateTx(ctx context.Context, tx pgx.Tx, in CreateInput) (Created, error) {
	return s.create(ctx, tx, in)
}

func (s *Store) create(ctx context.Context, ex executor, in CreateInput) (Created, error) {
	token := crypto.GenerateToken()
	idHash := crypto.HashToken(token)
	now := time.Now().UTC()
	expiresAt := now.Add(s.cfg.Lifetime)

	_, err := ex.Exec(ctx, `
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
// threshold window, not per request), never past the absolute
// created_at+MaxLifetime cap. Expired sessions — and sessions whose
// owner has been disabled — are deleted opportunistically.
func (s *Store) Validate(ctx context.Context, token string) (Result, error) {
	idHash := crypto.HashToken(token)

	var (
		userID    string
		createdAt time.Time
		expiresAt time.Time
		lastUsed  time.Time
		u         user.User
		name      *string
		picture   *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT s.user_id, s.created_at, s.expires_at, s.last_used_at,
		       u.id, u.email, u.email_verified, u.name, u.picture_url,
		       u.created_at, u.metadata, u.disabled
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.id_hash = $1`, idHash).
		Scan(&userID, &createdAt, &expiresAt, &lastUsed,
			&u.ID, &u.Email, &u.EmailVerified, &name, &picture,
			&u.CreatedAt, &u.Metadata, &u.Disabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{Kind: KindNotFound}, nil
		}
		return Result{}, err
	}
	u.Name = name
	u.PictureURL = picture

	now := time.Now().UTC()
	// A disabled account's live sessions die on next use. Same outcome as
	// expiry for every caller, and the row goes away so a stolen cookie
	// cannot outlive the disable even if the flag is later cleared.
	if u.Disabled || !expiresAt.After(now) {
		_, _ = s.pool.Exec(ctx, `DELETE FROM sessions WHERE id_hash = $1`, idHash)
		return Result{Kind: KindExpired}, nil
	}

	renewed := false
	if now.Sub(lastUsed) >= s.cfg.RollingRenewalThreshold {
		newExpiry := now.Add(s.cfg.Lifetime)
		if s.cfg.MaxLifetime > 0 {
			if limit := createdAt.Add(s.cfg.MaxLifetime); newExpiry.After(limit) {
				newExpiry = limit
			}
		}
		if newExpiry.After(expiresAt) {
			if _, err := s.pool.Exec(ctx, `
				UPDATE sessions SET last_used_at = $2, expires_at = $3
				WHERE id_hash = $1`, idHash, now, newExpiry); err != nil {
				return Result{}, err
			}
			expiresAt = newExpiry
			renewed = true
		} else {
			// Pinned against the absolute cap: no extension to make, but
			// still record the touch so the renewal window does not retry
			// this branch on every subsequent request.
			if _, err := s.pool.Exec(ctx, `
				UPDATE sessions SET last_used_at = $2 WHERE id_hash = $1`,
				idHash, now); err != nil {
				return Result{}, err
			}
		}
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
	return revoke(ctx, s.pool, token)
}

// RevokeTx is Revoke inside a caller-owned transaction.
func (s *Store) RevokeTx(ctx context.Context, tx pgx.Tx, token string) (string, error) {
	return revoke(ctx, tx, token)
}

func revoke(ctx context.Context, ex executor, token string) (string, error) {
	idHash := crypto.HashToken(token)
	var userID string
	err := ex.QueryRow(ctx,
		`DELETE FROM sessions WHERE id_hash = $1 RETURNING user_id`, idHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return userID, err
}

// RevokeAllForUser deletes every session for a user ("log out everywhere").
func (s *Store) RevokeAllForUser(ctx context.Context, userID string) error {
	return revokeAllForUser(ctx, s.pool, userID)
}

// RevokeAllForUserTx is RevokeAllForUser inside a caller-owned transaction.
func (s *Store) RevokeAllForUserTx(ctx context.Context, tx pgx.Tx, userID string) error {
	return revokeAllForUser(ctx, tx, userID)
}

func revokeAllForUser(ctx context.Context, ex executor, userID string) error {
	_, err := ex.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
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
