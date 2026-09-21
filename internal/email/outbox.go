package email

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcibernet/sesamo/internal/crypto"
)

// Metrics is the counter/gauge surface the outbox and its worker need.
// Declared here (not imported) so the email package does not depend on
// the metrics registry, and so tests can observe emissions with three
// lines of fake.
type Metrics interface {
	IncCounter(name string)
	SetGauge(name string, v float64)
}

// Outbox metric names. Fixed cardinality by construction: no email,
// user id, outbox id or provider message id ever becomes part of a name.
const (
	MetricAccepted               = "sesamo_email_outbox_accepted_total"
	MetricDelivered              = "sesamo_email_outbox_delivered_total"
	MetricFailed                 = "sesamo_email_outbox_failed_total"
	MetricExpired                = "sesamo_email_outbox_expired_total"
	MetricCanceled               = "sesamo_email_outbox_canceled_total"
	MetricRetries                = "sesamo_email_outbox_retries_total"
	MetricDecryptErrors          = "sesamo_email_outbox_decrypt_errors_total"
	MetricLeaseLost              = "sesamo_email_outbox_lease_lost_total"
	MetricWebhookEvents          = "sesamo_email_outbox_webhook_events_total"
	MetricWebhookSignatureErrors = "sesamo_email_outbox_webhook_signature_errors_total"

	// Queue health drives the "oldest pending job older than two
	// minutes" alert; gauges, because a rate says nothing about backlog.
	GaugePending              = "sesamo_email_outbox_pending"
	GaugeOldestPendingSeconds = "sesamo_email_outbox_oldest_pending_seconds"
)

const (
	// MaxAttempts is the hard attempt ceiling. send_before usually ends a
	// job first; this bounds the pathological case where a provider keeps
	// answering 5xx inside a long verification window.
	MaxAttempts = 12

	// LeaseDuration is how long a claimed job belongs to one worker. It
	// must exceed the send timeout so a live send never races the
	// recovery of its own job; a crashed worker's job comes back after it.
	LeaseDuration = 2 * time.Minute
)

// Terminal reasons written to email_outbox.last_error by the outbox
// itself (adapter codes come from SendError.Code).
const (
	reasonSendWindowElapsed = "send_window_elapsed"
	reasonMaxAttempts       = "max_attempts"
	reasonSuperseded        = "superseded"
	reasonTokenInactive     = "token_inactive"
	reasonDecryptFailed     = "decrypt_failed"
)

// ErrLeaseLost reports that a finalize did not match: the job was taken
// over by another worker after this one's lease expired. The new owner
// owns the outcome, so the loser must not retry or alarm.
var ErrLeaseLost = errors.New("email: outbox lease no longer held")

// Outbox is the durable queue for transactional auth mail. Handlers
// enqueue inside their own transaction; the worker delivers outside it.
type Outbox struct {
	pool    *pgxpool.Pool
	keyring *Keyring
	log     *slog.Logger
	metrics Metrics
}

// NewOutbox constructs an Outbox. keyring is required: without it a
// queued payload would sit in Postgres as a usable bearer link.
func NewOutbox(pool *pgxpool.Pool, keyring *Keyring, log *slog.Logger, m Metrics) *Outbox {
	return &Outbox{pool: pool, keyring: keyring, log: log, metrics: nopMetrics(m)}
}

// QueueInput is one message to deliver. Body is the only secret field:
// it embeds the one-time link.
type QueueInput struct {
	UserID   string
	TokenID  string // "" when the mail carries no one-time link
	To       string
	From     string
	Subject  string
	Body     string
	Purpose  Purpose
	Provider string
	// SendBefore is the deadline after which the link is too close to its
	// own expiry to be worth delivering.
	SendBefore time.Time
}

// QueueTx enqueues a message in the caller's transaction, encrypting the
// payload before it touches Postgres, and cancels the jobs of any links
// this one supersedes (same user, same purpose). Cancellation runs first
// so the row being inserted cannot cancel itself.
//
// A rolled-back transaction leaves neither token nor job: that atomicity
// is the whole reason the enqueue lives here instead of in the handler.
func (o *Outbox) QueueTx(ctx context.Context, tx pgx.Tx, in QueueInput) error {
	id := crypto.UUIDv7()
	keyID, nonce, ciphertext, err := o.keyring.Encrypt([]byte(in.Body), payloadAAD(id, in.Provider, string(in.Purpose)))
	if err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE email_outbox
		   SET status = 'canceled', canceled_at = now(), updated_at = now(),
		       nonce = NULL, ciphertext = NULL,
		       lease_token = NULL, lease_until = NULL,
		       last_error = $3
		 WHERE user_id = $1 AND purpose = $2 AND status = 'pending'`,
		in.UserID, string(in.Purpose), reasonSuperseded); err != nil {
		return err
	}

	var tokenID any
	if in.TokenID != "" {
		tokenID = in.TokenID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO email_outbox
		    (id, user_id, token_id, provider, purpose, recipient, sender, subject,
		     key_id, nonce, ciphertext, send_before)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		id, in.UserID, tokenID, in.Provider, string(in.Purpose), in.To, in.From, in.Subject,
		keyID, nonce, ciphertext, in.SendBefore)
	return err
}

// Job is a claimed, decrypted message the worker must deliver.
type Job struct {
	ID         string
	UserID     string
	Provider   string
	Purpose    Purpose
	Attempt    int    // 1 on the first delivery attempt
	LeaseToken string // finalize is scoped to this value
	LeaseUntil time.Time
	SendBefore time.Time
	Message    Message
}

// IdempotencyKey is what the provider deduplicates on. Derived from the
// immutable outbox id, so every retry — including one after a crash that
// lost the acceptance — presents the same key with the same payload.
func (j Job) IdempotencyKey() string { return "auth-email/" + j.ID }

// claimed is a locked candidate row before it is classified.
type claimed struct {
	job        Job
	keyID      string
	nonce      []byte
	ciphertext []byte
	attempts   int
	hasToken   bool
	tokenLive  bool
}

// Claim leases up to limit deliverable jobs frozen to provider.
//
// The provider filter is a correctness rule, not an optimization: each
// row froze its provider at enqueue time, and this worker holds exactly
// one adapter. Claiming a row queued for a different provider would send
// it through credentials it was never meant for after an operator
// switches SESAMO_EMAIL_PROVIDER with mail still in flight. Rows left
// behind by a switch are removed by PurgeFinished once their send window
// lapses.
//
// The lock is held for one short transaction: candidates are locked with
// FOR UPDATE SKIP LOCKED (so N workers partition the backlog instead of
// serializing on it), jobs that can no longer be delivered are retired
// in that same transaction, and the survivors get an attempt increment
// plus a fresh lease. Decryption and the provider call happen after the
// commit — a transaction must never span an outbound HTTP request.
//
// Retired in-claim: the send window elapsed (expired), the attempt
// ceiling is reached (failed), or the link the mail carries is no longer
// live (canceled) — a superseded or already-spent token means the email
// would deliver a dead link.
func (o *Outbox) Claim(ctx context.Context, provider string, limit int) ([]Job, error) {
	tx, err := o.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT o.id, o.user_id, o.provider, o.purpose, o.recipient, o.subject,
		       o.key_id, o.nonce, o.ciphertext, o.attempt_count, o.send_before,
		       o.token_id IS NOT NULL AS has_token,
		       (t.id IS NOT NULL AND t.consumed_at IS NULL AND t.expires_at > now()) AS token_live
		  FROM email_outbox o
		  LEFT JOIN one_time_tokens t ON t.id = o.token_id
		 WHERE o.status = 'pending' AND o.provider = $1 AND o.available_at <= now()
		   -- A live lease means another worker owns this job right now.
		   -- An expired one means its owner died mid-send: reclaiming is
		   -- exactly the recovery path (the provider idempotency key
		   -- keeps the replay from duplicating the mail).
		   AND (o.lease_until IS NULL OR o.lease_until <= now())
		 ORDER BY o.available_at
		 LIMIT $2
		 FOR UPDATE OF o SKIP LOCKED`, provider, limit)
	if err != nil {
		return nil, err
	}
	var candidates []claimed
	for rows.Next() {
		var c claimed
		var purpose string
		if err := rows.Scan(&c.job.ID, &c.job.UserID, &c.job.Provider, &purpose,
			&c.job.Message.To, &c.job.Message.Subject,
			&c.keyID, &c.nonce, &c.ciphertext, &c.attempts, &c.job.SendBefore,
			&c.hasToken, &c.tokenLive); err != nil {
			rows.Close()
			return nil, err
		}
		c.job.Purpose = Purpose(purpose)
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	now := time.Now()
	var expired, exhausted, dead, leasable []string
	leasableBy := make(map[string]claimed, len(candidates))
	for _, c := range candidates {
		switch {
		case !c.job.SendBefore.After(now):
			expired = append(expired, c.job.ID)
		case c.attempts >= MaxAttempts:
			exhausted = append(exhausted, c.job.ID)
		case c.hasToken && !c.tokenLive:
			dead = append(dead, c.job.ID)
		default:
			leasable = append(leasable, c.job.ID)
			leasableBy[c.job.ID] = c
		}
	}

	if err := o.retire(ctx, tx, expired, "expired", reasonSendWindowElapsed); err != nil {
		return nil, err
	}
	if err := o.retire(ctx, tx, exhausted, "failed", reasonMaxAttempts); err != nil {
		return nil, err
	}
	if err := o.retire(ctx, tx, dead, "canceled", reasonTokenInactive); err != nil {
		return nil, err
	}

	jobs := make([]Job, 0, len(leasable))
	if len(leasable) > 0 {
		// gen_random_uuid() per row: each job gets its own lease token, so
		// one worker losing a lease cannot let it finalize another job.
		leaseRows, err := tx.Query(ctx, `
			UPDATE email_outbox
			   SET attempt_count = attempt_count + 1,
			       lease_token = gen_random_uuid(),
			       lease_until = now() + make_interval(secs => $2),
			       updated_at = now()
			 WHERE id = ANY($1::uuid[])
			RETURNING id, attempt_count, lease_token, lease_until`,
			leasable, LeaseDuration.Seconds())
		if err != nil {
			return nil, err
		}
		for leaseRows.Next() {
			var id, leaseToken string
			var attempt int
			var leaseUntil time.Time
			if err := leaseRows.Scan(&id, &attempt, &leaseToken, &leaseUntil); err != nil {
				leaseRows.Close()
				return nil, err
			}
			c := leasableBy[id]
			c.job.Attempt = attempt
			c.job.LeaseToken = leaseToken
			c.job.LeaseUntil = leaseUntil
			leasableBy[id] = c
		}
		leaseRows.Close()
		if err := leaseRows.Err(); err != nil {
			return nil, err
		}
		for _, id := range leasable {
			jobs = append(jobs, leasableBy[id].job)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	for range expired {
		o.metrics.IncCounter(MetricExpired)
	}
	for range exhausted {
		o.metrics.IncCounter(MetricFailed)
	}
	for range dead {
		o.metrics.IncCounter(MetricCanceled)
	}

	// Decrypt only after the lock is released. A payload we cannot open
	// (key dropped from the keyring, tampered row) can never be sent:
	// retire it terminally instead of burning the attempt budget.
	out := jobs[:0]
	for _, job := range jobs {
		c := leasableBy[job.ID]
		body, err := o.keyring.Decrypt(c.keyID, c.nonce, c.ciphertext,
			payloadAAD(job.ID, job.Provider, string(job.Purpose)))
		if err != nil {
			o.metrics.IncCounter(MetricDecryptErrors)
			o.log.Error("email outbox payload undecryptable", "outbox_id", job.ID, "key_id", c.keyID, "err", err)
			if ferr := o.Finalize(ctx, job.ID, job.LeaseToken, Outcome{
				Kind: OutcomeFailed, Code: reasonDecryptFailed,
			}); ferr != nil && !errors.Is(ferr, ErrLeaseLost) {
				o.log.Error("email outbox finalize decrypt failure", "outbox_id", job.ID, "err", ferr)
			}
			continue
		}
		job.Message.Body = string(body)
		out = append(out, job)
	}
	return out, nil
}

// retire moves jobs out of 'pending' for good and erases their payload.
func (o *Outbox) retire(ctx context.Context, tx pgx.Tx, ids []string, status, reason string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `
		UPDATE email_outbox
		   SET status = $2,
		       failed_at   = CASE WHEN $2 = 'failed'   THEN now() ELSE failed_at   END,
		       expired_at  = CASE WHEN $2 = 'expired'  THEN now() ELSE expired_at  END,
		       canceled_at = CASE WHEN $2 = 'canceled' THEN now() ELSE canceled_at END,
		       last_error = $3, nonce = NULL, ciphertext = NULL,
		       lease_token = NULL, lease_until = NULL, updated_at = now()
		 WHERE id = ANY($1::uuid[])`, ids, status, reason)
	return err
}

// OutcomeKind is what the worker decided about a delivery attempt.
type OutcomeKind int

const (
	// OutcomeAccepted: the provider took the message. Not delivered — the
	// webhook decides that.
	OutcomeAccepted OutcomeKind = iota
	// OutcomeRetry: transient failure; the job goes back to pending.
	OutcomeRetry
	// OutcomeFailed: terminal failure; the job is done and its payload dies.
	OutcomeFailed
)

// Outcome is the result of one delivery attempt. The worker owns the
// retry policy, so RetryIn arrives already resolved (provider
// Retry-After or exponential backoff with full jitter).
type Outcome struct {
	Kind              OutcomeKind
	ProviderMessageID string
	Code              string
	RetryIn           time.Duration
}

// Finalize records the outcome of a delivery attempt.
//
// Every update is scoped by id AND lease_token, so a worker whose lease
// expired mid-send cannot overwrite the state written by the job's new
// owner; it gets ErrLeaseLost and stays quiet.
//
// Accepting also erases nonce and ciphertext: from that point on the mail
// is the provider's problem, and the link no longer needs to exist in
// Postgres. Then any delivery events that arrived before the provider
// message id was known are replayed onto the row.
func (o *Outbox) Finalize(ctx context.Context, id, leaseToken string, out Outcome) error {
	var sql string
	var args []any
	switch out.Kind {
	case OutcomeAccepted:
		sql = `
			UPDATE email_outbox
			   SET status = 'accepted', accepted_at = now(), provider_message_id = $3,
			       nonce = NULL, ciphertext = NULL, last_error = NULL,
			       lease_token = NULL, lease_until = NULL, updated_at = now()
			 WHERE id = $1 AND lease_token = $2`
		args = []any{id, leaseToken, out.ProviderMessageID}
	case OutcomeRetry:
		sql = `
			UPDATE email_outbox
			   SET available_at = now() + make_interval(secs => $4),
			       last_error = $3, lease_token = NULL, lease_until = NULL,
			       updated_at = now()
			 WHERE id = $1 AND lease_token = $2 AND status = 'pending'`
		args = []any{id, leaseToken, out.Code, out.RetryIn.Seconds()}
	case OutcomeFailed:
		sql = `
			UPDATE email_outbox
			   SET status = 'failed', failed_at = now(), last_error = $3,
			       nonce = NULL, ciphertext = NULL,
			       lease_token = NULL, lease_until = NULL, updated_at = now()
			 WHERE id = $1 AND lease_token = $2`
		args = []any{id, leaseToken, out.Code}
	default:
		return fmt.Errorf("email: unknown outbox outcome %d", out.Kind)
	}

	tag, err := o.pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	if out.Kind == OutcomeAccepted && out.ProviderMessageID != "" {
		return o.reconcileEvents(ctx, out.ProviderMessageID)
	}
	return nil
}

// Provider event types Sésamo subscribes to. Click and open events are
// absent on purpose: tracking stays disabled, and a rewritten bearer
// link is a security regression.
const (
	EventSent            = "email.sent"
	EventDelivered       = "email.delivered"
	EventDeliveryDelayed = "email.delivery_delayed"
	EventBounced         = "email.bounced"
	EventComplained      = "email.complained"
	EventFailed          = "email.failed"
	EventSuppressed      = "email.suppressed"
)

// RecordProviderEvent stores a verified delivery event and folds it into
// the operational state of its outbox row.
//
// svix_id UNIQUE is the replay guard: a duplicate delivery inserts
// nothing and returns applied=false, so a replayed complaint cannot
// re-trigger anything. The reducer is monotonic — see reduceEvent.
func (o *Outbox) RecordProviderEvent(ctx context.Context, svixID, providerMessageID, eventType string, occurredAt time.Time) (bool, error) {
	tag, err := o.pool.Exec(ctx, `
		INSERT INTO email_events (svix_id, provider_message_id, event_type, occurred_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (svix_id) DO NOTHING`,
		svixID, providerMessageID, eventType, occurredAt)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	o.metrics.IncCounter(MetricWebhookEvents)
	o.metrics.IncCounter(MetricWebhookEvents + "_" + eventTypeLabel(eventType))
	return true, o.reduceEvent(ctx, providerMessageID, eventType, occurredAt)
}

// reduceEvent applies one event to the outbox row, never walking the
// state backwards.
//
// Provider events are unordered by nature (a delivered can arrive after
// a complaint, a sent after a delivered). The rules:
//
//   - delivered stamps delivered_at as evidence, but only promotes the
//     status while the job is still pending/accepted;
//   - bounce, complaint, failure and suppression are terminal and DO
//     overwrite a delivered status: "delivered, then complained about" is
//     operationally a failure, and hiding the complaint behind the
//     delivery is what a reputation problem looks like right before it
//     becomes a blocked domain. delivered_at stays set, so the full
//     sequence remains readable on the row;
//   - sent only rescues a row whose local accept update was lost;
//   - delivery_delayed is informational and touches no status.
func (o *Outbox) reduceEvent(ctx context.Context, providerMessageID, eventType string, occurredAt time.Time) error {
	switch eventType {
	case EventDelivered:
		if _, err := o.pool.Exec(ctx, `
			UPDATE email_outbox
			   SET delivered_at = COALESCE(delivered_at, $2),
			       status = CASE WHEN status IN ('pending', 'accepted') THEN 'delivered' ELSE status END,
			       nonce = NULL, ciphertext = NULL, updated_at = now()
			 WHERE provider_message_id = $1`, providerMessageID, occurredAt); err != nil {
			return err
		}
		o.metrics.IncCounter(MetricDelivered)
		return nil
	case EventBounced, EventComplained, EventFailed, EventSuppressed:
		if _, err := o.pool.Exec(ctx, `
			UPDATE email_outbox
			   SET status = 'failed', failed_at = COALESCE(failed_at, $2), last_error = $3,
			       nonce = NULL, ciphertext = NULL, updated_at = now()
			 WHERE provider_message_id = $1`, providerMessageID, occurredAt, eventType); err != nil {
			return err
		}
		o.metrics.IncCounter(MetricFailed)
		return nil
	case EventSent:
		_, err := o.pool.Exec(ctx, `
			UPDATE email_outbox
			   SET status = 'accepted', accepted_at = COALESCE(accepted_at, $2), updated_at = now()
			 WHERE provider_message_id = $1 AND status = 'pending'`, providerMessageID, occurredAt)
		return err
	case EventDeliveryDelayed:
		_, err := o.pool.Exec(ctx, `
			UPDATE email_outbox
			   SET last_error = $2, updated_at = now()
			 WHERE provider_message_id = $1 AND status IN ('pending', 'accepted')`,
			providerMessageID, eventType)
		return err
	default:
		// Unknown type: kept in email_events for forensics, ignored here.
		// Guessing a status transition from an unrecognized event is how a
		// working mail flow gets marked failed by a provider changelog.
		return nil
	}
}

// reconcileEvents replays events that were stored before this row knew
// its provider message id (the webhook can beat our own accept update).
func (o *Outbox) reconcileEvents(ctx context.Context, providerMessageID string) error {
	rows, err := o.pool.Query(ctx, `
		SELECT event_type, occurred_at FROM email_events
		 WHERE provider_message_id = $1 ORDER BY occurred_at, id`, providerMessageID)
	if err != nil {
		return err
	}
	type event struct {
		typ string
		at  time.Time
	}
	var events []event
	for rows.Next() {
		var e event
		if err := rows.Scan(&e.typ, &e.at); err != nil {
			rows.Close()
			return err
		}
		events = append(events, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, e := range events {
		if err := o.reduceEvent(ctx, providerMessageID, e.typ, e.at); err != nil {
			return err
		}
	}
	return nil
}

// Stats is queue health for the gauges: how many jobs are waiting and
// how long the oldest one has been ready to send.
type Stats struct {
	Pending          int
	OldestPendingAge time.Duration
}

// QueueStats samples this provider's pending backlog. Served by
// ix_email_outbox_pending. Scoped like Claim: the gauge answers "is MY
// worker keeping up", and rows stranded by a provider switch would
// otherwise page an operator about mail no worker will ever send.
func (o *Outbox) QueueStats(ctx context.Context, provider string) (Stats, error) {
	var pending int
	var oldest *time.Time
	err := o.pool.QueryRow(ctx, `
		SELECT count(*), min(available_at) FROM email_outbox
		 WHERE status = 'pending' AND provider = $1`, provider).
		Scan(&pending, &oldest)
	if err != nil {
		return Stats{}, err
	}
	st := Stats{Pending: pending}
	if oldest != nil {
		if age := time.Since(*oldest); age > 0 {
			st.OldestPendingAge = age
		}
	}
	return st, nil
}

// PurgeFinished deletes jobs that can no longer change and the delivery
// events that belonged to them. Retention here is short on purpose: the
// business evidence lives in audit_log, this table is an execution log.
//
// Pending rows whose send window lapsed longer than the retention ago
// are included: a provider switch strands pending rows no worker claims
// anymore (Claim filters by provider), and nothing else retires them.
func (o *Outbox) PurgeFinished(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := o.pool.Exec(ctx, `
		DELETE FROM email_outbox
		 WHERE (status <> 'pending' AND updated_at < now() - make_interval(secs => $1))
		    OR (status = 'pending' AND send_before < now() - make_interval(secs => $1))`,
		olderThan.Seconds())
	if err != nil {
		return 0, err
	}
	removed := tag.RowsAffected()
	// Events outlive their row only as orphans; drop them on the same
	// clock so replay protection covers at least the retention window.
	evTag, err := o.pool.Exec(ctx, `
		DELETE FROM email_events
		 WHERE received_at < now() - make_interval(secs => $1)`, olderThan.Seconds())
	if err != nil {
		return removed, err
	}
	return removed + evTag.RowsAffected(), nil
}

// payloadAAD binds a ciphertext to its row: id, provider and purpose are
// authenticated, so a payload moved to another row (or replayed against a
// different provider) fails to open instead of being sent.
func payloadAAD(id, provider, purpose string) []byte {
	return []byte(id + "|" + provider + "|" + purpose)
}

// eventTypeLabel keeps per-event counter names bounded to the catalog
// Sésamo subscribes to; anything else shares one "other" bucket.
func eventTypeLabel(eventType string) string {
	switch eventType {
	case EventSent, EventDelivered, EventDeliveryDelayed, EventBounced,
		EventComplained, EventFailed, EventSuppressed:
		return strings.ReplaceAll(eventType, ".", "_")
	default:
		return "other"
	}
}

// nopMetrics keeps every emission site free of nil checks.
func nopMetrics(m Metrics) Metrics {
	if m == nil {
		return discardMetrics{}
	}
	return m
}

type discardMetrics struct{}

func (discardMetrics) IncCounter(string)        {}
func (discardMetrics) SetGauge(string, float64) {}
