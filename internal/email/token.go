package email

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcibernet/sesamo/internal/crypto"
)

// Purpose enumerates one-time-token kinds.
type Purpose string

const (
	PurposeReset     Purpose = "reset"
	PurposeVerify    Purpose = "verify"
	PurposeMagicLink Purpose = "magiclink"
)

// TokenStore manages single-use tokens for email-driven flows.
type TokenStore struct {
	pool *pgxpool.Pool
}

// NewTokenStore constructs a TokenStore.
func NewTokenStore(pool *pgxpool.Pool) *TokenStore {
	return &TokenStore{pool: pool}
}

// Issue creates a one-time token for a user and purpose, returning the
// raw token (sent via email). Only the hash is stored. Any prior
// unconsumed tokens of the same purpose for that user are invalidated so
// only the newest link works.
func (s *TokenStore) Issue(ctx context.Context, userID string, purpose Purpose, ttl time.Duration) (string, error) {
	token := crypto.GenerateToken()
	hash := crypto.HashToken(token)
	now := time.Now().UTC()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`UPDATE one_time_tokens SET consumed_at = $3
		 WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL`,
		userID, string(purpose), now); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO one_time_tokens (id, user_id, token_hash, purpose, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		crypto.UUIDv7(), userID, hash, string(purpose), now.Add(ttl)); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return token, nil
}

// ErrInvalidToken is returned when a token is missing, expired, or used.
var ErrInvalidToken = errors.New("invalid or expired token")

// executor is the subset of *pgxpool.Pool and pgx.Tx the store needs, so
// the single-use UPDATE lives exactly once and the pooled and
// transactional entry points cannot drift apart.
type executor interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Consume atomically validates and marks a token used, returning the
// associated user id. A token can be consumed at most once.
func (s *TokenStore) Consume(ctx context.Context, token string, purpose Purpose) (string, error) {
	return consume(ctx, s.pool, token, purpose)
}

// ConsumeTx is Consume inside a caller-owned transaction, so spending
// the token and everything the caller does with the result — the session
// row, the evidence row — commit or roll back together. Rolling back
// un-spends the token: the emailed link stays usable, which is the point
// (the alternative is a user locked out by a failed audit write).
func (s *TokenStore) ConsumeTx(ctx context.Context, tx pgx.Tx, token string, purpose Purpose) (string, error) {
	return consume(ctx, tx, token, purpose)
}

func consume(ctx context.Context, ex executor, token string, purpose Purpose) (string, error) {
	hash := crypto.HashToken(token)
	var userID string
	// Single UPDATE ... RETURNING guarantees atomic single-use: the row
	// is only returned if it was still unconsumed and unexpired.
	err := ex.QueryRow(ctx,
		`UPDATE one_time_tokens
		   SET consumed_at = now()
		 WHERE token_hash = $1
		   AND purpose = $2
		   AND consumed_at IS NULL
		   AND expires_at > now()
		 RETURNING user_id`,
		hash, string(purpose)).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidToken
	}
	if err != nil {
		return "", err
	}
	return userID, nil
}

// PurgeExpired deletes tokens that can never be consumed again: expired
// or already used. Consume requires consumed_at IS NULL and an unexpired
// row, so these are dead weight; the audit log is the forensic record.
// Intended to be called from a periodic job.
func (s *TokenStore) PurgeExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM one_time_tokens WHERE expires_at <= now() OR consumed_at IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
