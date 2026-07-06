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
// a token is available. Refill and consume run inside one transaction:
// the upsert takes the row lock, so concurrent instances serialize on
// the bucket and cannot oversubscribe.
func (l *Limiter) Allow(ctx context.Context, key string, rule Rule) (bool, time.Duration, error) {
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The bucket starts full. On each call we refill based on elapsed
	// time, clamp to capacity, then try to spend one token. The row
	// stays locked until commit.
	var tokens float64
	err = tx.QueryRow(ctx, `
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
		if _, err := tx.Exec(ctx,
			`UPDATE rate_limit_buckets SET tokens = tokens - 1 WHERE key = $1`, key); err != nil {
			return false, 0, err
		}
		if err := tx.Commit(ctx); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	}

	// Not enough tokens: commit the refill bookkeeping and report the
	// time until one token is available.
	if err := tx.Commit(ctx); err != nil {
		return false, 0, err
	}
	needed := 1 - tokens
	wait := time.Duration(needed / rule.RefillPerSec * float64(time.Second))
	return false, wait, nil
}

// PurgeStale deletes buckets not touched for olderThan. A bucket that
// old has fully refilled, so deleting it is behaviorally a no-op — this
// only bounds table growth (an attacker rotating keys, e.g. spoofed
// client IPs, would otherwise grow rate_limit_buckets without limit).
// Intended to be called from a periodic job.
func (l *Limiter) PurgeStale(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := l.pool.Exec(ctx,
		`DELETE FROM rate_limit_buckets WHERE updated_at < now() - make_interval(secs => $1)`,
		olderThan.Seconds())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
