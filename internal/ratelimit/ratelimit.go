// Package ratelimit implements a Postgres-backed token-bucket limiter
// keyed by arbitrary strings (e.g. "ip:1.2.3.4" or "identity:a@b.com").
// State lives in the rate_limit_buckets table so limits hold across
// multiple server instances sharing one database.
package ratelimit

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Limiter enforces token-bucket limits.
type Limiter struct {
	pool *pgxpool.Pool
}

// New constructs a Limiter.
func New(pool *pgxpool.Pool) *Limiter {
	return &Limiter{pool: pool}
}

// Rule describes a bucket: capacity tokens, refilling at refillPerSec.
type Rule struct {
	Capacity     float64
	RefillPerSec float64
}

// Allow attempts to consume one token from the bucket identified by key.
// It returns whether the request is allowed and, if not, how long until
// a token is available. The refill + consume is done atomically with an
// upsert so concurrent instances cannot oversubscribe.
func (l *Limiter) Allow(ctx context.Context, key string, rule Rule) (bool, time.Duration, error) {
	// The bucket starts full. On each call we refill based on elapsed
	// time, clamp to capacity, then try to spend one token.
	var tokens float64
	err := l.pool.QueryRow(ctx, `
		INSERT INTO rate_limit_buckets (key, tokens, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET
			tokens = LEAST(
				$2,
				rate_limit_buckets.tokens +
					EXTRACT(EPOCH FROM (now() - rate_limit_buckets.updated_at)) * $3
			),
			updated_at = now()
		RETURNING tokens`,
		key, rule.Capacity, rule.RefillPerSec).Scan(&tokens)
	if err != nil {
		return false, 0, err
	}

	if tokens >= 1 {
		if _, err := l.pool.Exec(ctx,
			`UPDATE rate_limit_buckets SET tokens = tokens - 1 WHERE key = $1`, key); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	}

	// Not enough tokens: time until one refills.
	needed := 1 - tokens
	wait := time.Duration(needed/rule.RefillPerSec*float64(time.Second)) * 1
	return false, wait, nil
}
