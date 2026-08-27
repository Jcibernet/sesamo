package email

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"
)

const (
	// pollInterval is how often an idle worker looks for work. Auth mail
	// is latency-sensitive (a user is staring at an inbox), so this is
	// short; the query is an index-only scan over the pending partial
	// index.
	pollInterval = 2 * time.Second

	// claimBatch bounds how many jobs one cycle leases. Sends are
	// sequential, so a batch must be deliverable well inside LeaseDuration.
	claimBatch = 10

	// sendTimeout bounds one provider call. The shared outbound client
	// already caps the HTTP operation; this also covers the retry-free
	// body read and keeps a shutdown bounded.
	sendTimeout = 20 * time.Second

	// statsInterval throttles the queue-health sample: gauges do not need
	// to be refreshed on every poll.
	statsInterval = 15 * time.Second

	// backoffBase and backoffCap frame the exponential backoff.
	backoffBase = 2 * time.Second
	backoffCap  = 5 * time.Minute
	// backoffFloor keeps full jitter from scheduling an instant retry
	// against a provider that just failed.
	backoffFloor = time.Second
)

// Worker delivers queued mail for one provider. Every replica may run
// one: jobs are partitioned by FOR UPDATE SKIP LOCKED and owned by a
// lease, so N workers never deliver the same job twice. provider scopes
// every claim — rows are frozen to the provider that enqueued them, and
// this worker's sender only speaks for one.
type Worker struct {
	outbox   *Outbox
	provider string
	sender   Sender
	log      *slog.Logger
	metrics  Metrics
}

// NewWorker constructs a Worker over an outbox and the adapter for
// provider (the value of SESAMO_EMAIL_PROVIDER the sender was built for).
func NewWorker(outbox *Outbox, provider string, sender Sender, log *slog.Logger, m Metrics) *Worker {
	return &Worker{outbox: outbox, provider: provider, sender: sender, log: log, metrics: nopMetrics(m)}
}

// Run polls until ctx is done.
//
// Shutdown: cancelling ctx stops claiming, but the send already in
// flight — and its finalize — run on a context detached from ctx, so the
// process does not abandon a message whose acceptance it would then never
// record. Anything still leased at exit is recovered by another replica
// (or by this one on restart) when the lease expires.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	var lastStats time.Time

	for {
		if ctx.Err() != nil {
			return
		}
		if time.Since(lastStats) >= statsInterval {
			w.sampleQueue(ctx)
			lastStats = time.Now()
		}
		n := w.runOnce(ctx)

		// A full batch means there is probably more waiting: keep going
		// without paying the poll interval.
		if n == claimBatch {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Spread replicas out so they do not all wake on the same
			// tick and contend for the head of the queue.
			jitterSleep(ctx, pollInterval/4)
		}
	}
}

// runOnce claims and delivers one batch, returning how many jobs it
// processed. Exposed to tests as the single deterministic step.
func (w *Worker) runOnce(ctx context.Context) int {
	jobs, err := w.outbox.Claim(ctx, w.provider, claimBatch)
	if err != nil {
		if ctx.Err() == nil {
			w.log.Error("email outbox claim", "err", err)
		}
		return 0
	}
	for _, job := range jobs {
		w.deliver(ctx, job)
	}
	return len(jobs)
}

// deliver performs one attempt and records its outcome.
func (w *Worker) deliver(ctx context.Context, job Job) {
	// Detached from ctx on purpose (see Run): an in-flight send must
	// finish and be recorded even while the process is shutting down.
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sendTimeout)
	defer cancel()

	receipt, err := w.sender.Send(sendCtx, job.Message, job.IdempotencyKey())
	out := w.classify(job, receipt, err)

	if ferr := w.outbox.Finalize(sendCtx, job.ID, job.LeaseToken, out); ferr != nil {
		if errors.Is(ferr, ErrLeaseLost) {
			// Our lease expired and someone else owns this job now. Their
			// outcome stands; ours is dropped deliberately.
			w.metrics.IncCounter(MetricLeaseLost)
			w.log.Warn("email outbox lease lost before finalize",
				"outbox_id", job.ID, "attempt", job.Attempt)
			return
		}
		w.log.Error("email outbox finalize", "outbox_id", job.ID, "err", ferr)
	}
}

// classify turns a provider result into an outcome and its metric. Note
// what is NOT logged: recipient, subject, body, link and provider
// message id stay out of the record — only the outbox id, the attempt and
// a bounded error code.
func (w *Worker) classify(job Job, receipt Receipt, err error) Outcome {
	if err == nil {
		w.metrics.IncCounter(MetricAccepted)
		return Outcome{Kind: OutcomeAccepted, ProviderMessageID: receipt.ProviderMessageID}
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		// An adapter that returns a bare error gets the conservative
		// reading: unknown state, so retry under the same idempotency key.
		sendErr = &SendError{Retryable: true, Code: CodeTransport, err: err}
	}

	switch {
	case sendErr.Code == CodeIdempotencyClash:
		// Same key, different payload. The key is derived from an
		// immutable id, so this means something re-used it: an invariant
		// violation an operator has to see, never a retry.
		w.metrics.IncCounter(MetricFailed)
		w.log.Error("email outbox idempotency key reused with a different payload",
			"outbox_id", job.ID, "provider", job.Provider, "code", sendErr.Code)
		return Outcome{Kind: OutcomeFailed, Code: sendErr.Code}

	case sendErr.Retryable && job.Attempt < MaxAttempts:
		delay := Backoff(job.Attempt, sendErr.RetryAfter)
		// A retry scheduled past the send window is pointless: the job
		// would only be claimed to be expired.
		if time.Now().Add(delay).After(job.SendBefore) {
			w.metrics.IncCounter(MetricExpired)
			w.log.Warn("email outbox send window elapsed",
				"outbox_id", job.ID, "attempt", job.Attempt, "code", sendErr.Code)
			return Outcome{Kind: OutcomeFailed, Code: reasonSendWindowElapsed}
		}
		w.metrics.IncCounter(MetricRetries)
		w.log.Warn("email outbox delivery retry",
			"outbox_id", job.ID, "attempt", job.Attempt, "code", sendErr.Code,
			"retry_in_ms", delay.Milliseconds())
		return Outcome{Kind: OutcomeRetry, Code: sendErr.Code, RetryIn: delay}

	default:
		w.metrics.IncCounter(MetricFailed)
		w.log.Error("email outbox delivery failed",
			"outbox_id", job.ID, "attempt", job.Attempt, "code", sendErr.Code,
			"retryable", sendErr.Retryable)
		return Outcome{Kind: OutcomeFailed, Code: sendErr.Code}
	}
}

// sampleQueue publishes backlog gauges. A failure here is diagnostic
// only: it must never stop the worker from delivering mail.
func (w *Worker) sampleQueue(ctx context.Context) {
	st, err := w.outbox.QueueStats(ctx, w.provider)
	if err != nil {
		if ctx.Err() == nil {
			w.log.Warn("email outbox queue stats", "err", err)
		}
		return
	}
	w.metrics.SetGauge(GaugePending, float64(st.Pending))
	w.metrics.SetGauge(GaugeOldestPendingSeconds, st.OldestPendingAge.Seconds())
}

// Backoff returns when to try again. The provider's Retry-After wins
// when it sent one (capped, so a hostile or absurd value cannot park a
// job past its window); otherwise exponential backoff with full jitter,
// which spreads a fleet of workers recovering from a shared outage
// instead of synchronizing them into a thundering herd.
func Backoff(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return min(retryAfter, backoffCap)
	}
	ceiling := backoffCap
	if attempt < 32 {
		if scaled := backoffBase << uint(max(attempt-1, 0)); scaled < backoffCap {
			ceiling = scaled
		}
	}
	delay := time.Duration(rand.Int64N(int64(ceiling)) + 1)
	return max(delay, backoffFloor)
}

// jitterSleep waits a random slice of d, or returns early on shutdown.
func jitterSleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(time.Duration(rand.Int64N(int64(d)) + 1))
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
