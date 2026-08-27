package email

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeSender records what the worker asked it to send and replays a
// scripted outcome per attempt. It is the seam the retry, idempotency and
// shutdown behaviour is tested through.
type fakeSender struct {
	mu       sync.Mutex
	keys     []string
	bodies   []string
	outcomes []error // consumed in order; nil means accepted
	block    chan struct{}
	started  chan struct{}
}

func (f *fakeSender) Send(ctx context.Context, msg Message, idempotencyKey string) (Receipt, error) {
	f.mu.Lock()
	f.keys = append(f.keys, idempotencyKey)
	f.bodies = append(f.bodies, msg.Body)
	attempt := len(f.keys)
	var err error
	if attempt <= len(f.outcomes) {
		err = f.outcomes[attempt-1]
	}
	started, block := f.started, f.block
	f.mu.Unlock()

	if started != nil {
		started <- struct{}{}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return Receipt{}, ctx.Err()
		}
	}
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{ProviderMessageID: "provider-" + idempotencyKey}, nil
}

func (f *fakeSender) sentKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.keys...)
}

func (f *fakeSender) sentBodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.bodies...)
}

// A retry must present the SAME idempotency key and the SAME payload:
// that is what makes a crash between provider acceptance and our own
// update produce one email instead of two.
func TestWorkerRetryReusesIdempotencyKeyAndPayload(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	in := queueInput(uid, "", PurposeMagicLink)
	id := enqueue(t, o, in)
	ctx := context.Background()

	sender := &fakeSender{outcomes: []error{
		&SendError{Retryable: true, Code: CodeProviderError},
	}}
	w := NewWorker(o, "resend", sender, discardLogger(), m)

	if n := w.runOnce(ctx); n == 0 {
		t.Fatal("first cycle claimed nothing")
	}
	row := readJob(t, pool, id)
	if row.status != "pending" {
		t.Fatalf("status after retryable failure = %q, want pending", row.status)
	}
	if m.count(MetricRetries) != 1 {
		t.Fatalf("%s = %d, want 1", MetricRetries, m.count(MetricRetries))
	}

	// Make the backoff due and run the second cycle.
	if _, err := pool.Exec(ctx,
		`UPDATE email_outbox SET available_at = now() - interval '1 second' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if n := w.runOnce(ctx); n == 0 {
		t.Fatal("retry cycle claimed nothing")
	}

	keys := sentKeysFor(sender, id)
	if len(keys) != 2 {
		t.Fatalf("attempts = %d, want 2", len(keys))
	}
	if keys[0] != keys[1] || keys[0] != "auth-email/"+id {
		t.Fatalf("idempotency keys drifted: %v", keys)
	}
	bodies := bodiesFor(sender, in.Body)
	if len(bodies) != 2 {
		t.Fatalf("payload changed between attempts: %v", bodies)
	}

	row = readJob(t, pool, id)
	if row.status != "accepted" {
		t.Fatalf("status = %q, want accepted", row.status)
	}
	if row.providerMessageID == nil || *row.providerMessageID != "provider-auth-email/"+id {
		t.Fatalf("provider_message_id = %v", row.providerMessageID)
	}
	if row.attemptCount != 2 {
		t.Fatalf("attempt_count = %d, want 2", row.attemptCount)
	}
	if m.count(MetricAccepted) != 1 {
		t.Fatalf("%s = %d, want 1", MetricAccepted, m.count(MetricAccepted))
	}
}

func TestWorkerTerminalFailureStopsRetrying(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	ctx := context.Background()

	sender := &fakeSender{outcomes: []error{&SendError{Code: "validation_error"}}}
	w := NewWorker(o, "resend", sender, discardLogger(), m)
	w.runOnce(ctx)

	row := readJob(t, pool, id)
	if row.status != "failed" {
		t.Fatalf("status = %q, want failed", row.status)
	}
	if row.lastError == nil || *row.lastError != "validation_error" {
		t.Fatalf("last_error = %v", row.lastError)
	}
	if row.ciphertext != nil {
		t.Fatal("terminal job kept its payload")
	}
	if m.count(MetricFailed) != 1 {
		t.Fatalf("%s = %d, want 1", MetricFailed, m.count(MetricFailed))
	}
	// Nothing left to claim.
	if n := w.runOnce(ctx); n != 0 {
		t.Fatalf("claimed %d jobs after a terminal failure", n)
	}
}

// An idempotency-key clash means the same key arrived with a different
// payload: an invariant violation, never a retry.
func TestWorkerIdempotencyClashIsTerminal(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))

	sender := &fakeSender{outcomes: []error{
		&SendError{Retryable: true, Code: CodeIdempotencyClash},
	}}
	NewWorker(o, "resend", sender, discardLogger(), m).runOnce(context.Background())

	row := readJob(t, pool, id)
	if row.status != "failed" {
		t.Fatalf("status = %q, want failed", row.status)
	}
	if row.lastError == nil || *row.lastError != CodeIdempotencyClash {
		t.Fatalf("last_error = %v", row.lastError)
	}
}

// A retryable failure whose next attempt would land past send_before is
// finished now: claiming it again only to expire it wastes a cycle and
// hides the real outcome.
func TestWorkerStopsWhenRetryWouldOutliveSendWindow(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	in := queueInput(uid, "", PurposeMagicLink)
	in.SendBefore = time.Now().Add(500 * time.Millisecond)
	id := enqueue(t, o, in)

	sender := &fakeSender{outcomes: []error{
		&SendError{Retryable: true, Code: CodeRateLimited, RetryAfter: time.Minute},
	}}
	NewWorker(o, "resend", sender, discardLogger(), m).runOnce(context.Background())

	row := readJob(t, pool, id)
	if row.status != "failed" {
		t.Fatalf("status = %q, want failed", row.status)
	}
	if row.lastError == nil || *row.lastError != reasonSendWindowElapsed {
		t.Fatalf("last_error = %v", row.lastError)
	}
	if m.count(MetricExpired) != 1 {
		t.Fatalf("%s = %d, want 1", MetricExpired, m.count(MetricExpired))
	}
}

// Shutdown must not abandon a message the provider already accepted: the
// in-flight send and its finalize run on a context detached from the
// worker's, so cancelling mid-send still records the acceptance.
func TestWorkerShutdownFinishesInFlightSend(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))

	sender := &fakeSender{block: make(chan struct{}), started: make(chan struct{})}
	w := NewWorker(o, "resend", sender, discardLogger(), m)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		w.Run(ctx)
	}()

	select {
	case <-sender.started:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("worker never started a send")
	}
	// Shut down while the provider call is in flight, then let it answer.
	cancel()
	time.Sleep(50 * time.Millisecond)
	close(sender.block)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not exit after shutdown")
	}

	row := readJob(t, pool, id)
	if row.status != "accepted" {
		t.Fatalf("status = %q, want accepted (an accepted send must be recorded despite shutdown)", row.status)
	}
	if row.providerMessageID == nil {
		t.Fatal("provider_message_id lost on shutdown")
	}
}

// Two workers over the same queue must never deliver one job twice.
func TestTwoWorkersDeliverEachJobOnce(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)

	const jobs = 6
	ids := make([]string, 0, jobs)
	for range jobs {
		ids = append(ids, enqueue(t, o, queueInput(makeUser(t, pool), "", PurposeMagicLink)))
	}

	sender := &fakeSender{}
	ctx := context.Background()
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := NewWorker(o, "resend", sender, discardLogger(), m)
			// Two cycles each: enough for both to contend for the batch.
			w.runOnce(ctx)
			w.runOnce(ctx)
		}()
	}
	wg.Wait()

	counts := map[string]int{}
	for _, key := range sender.sentKeys() {
		counts[key]++
	}
	for _, id := range ids {
		key := "auth-email/" + id
		if counts[key] != 1 {
			t.Fatalf("job %s delivered %d times, want exactly 1", id, counts[key])
		}
		if got := readJob(t, pool, id).status; got != "accepted" {
			t.Fatalf("job %s status = %q, want accepted", id, got)
		}
	}
}

func TestWorkerSamplesQueueGauges(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	id := enqueue(t, o, queueInput(makeUser(t, pool), "", PurposeMagicLink))
	if _, err := pool.Exec(context.Background(),
		`UPDATE email_outbox SET available_at = now() - interval '3 minutes' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	NewWorker(o, "resend", &fakeSender{}, discardLogger(), m).sampleQueue(context.Background())
	if m.gauge(GaugePending) < 1 {
		t.Fatalf("%s = %v, want >= 1", GaugePending, m.gauge(GaugePending))
	}
	if m.gauge(GaugeOldestPendingSeconds) < 180 {
		t.Fatalf("%s = %v, want >= 180", GaugeOldestPendingSeconds, m.gauge(GaugeOldestPendingSeconds))
	}
}

func TestBackoff(t *testing.T) {
	// Retry-After wins, capped so a hostile value cannot park a job.
	if got := Backoff(1, 30*time.Second); got != 30*time.Second {
		t.Fatalf("Backoff with Retry-After = %v, want 30s", got)
	}
	if got := Backoff(1, time.Hour); got != backoffCap {
		t.Fatalf("Backoff with huge Retry-After = %v, want the cap %v", got, backoffCap)
	}
	// Full jitter: always within (0, ceiling] and never below the floor.
	for attempt := 1; attempt <= MaxAttempts+4; attempt++ {
		ceiling := backoffCap
		if scaled := backoffBase << uint(attempt-1); attempt < 32 && scaled < backoffCap {
			ceiling = scaled
		}
		for range 50 {
			got := Backoff(attempt, 0)
			if got < backoffFloor {
				t.Fatalf("attempt %d: backoff %v below floor %v", attempt, got, backoffFloor)
			}
			if got > max(ceiling, backoffFloor) {
				t.Fatalf("attempt %d: backoff %v above ceiling %v", attempt, got, ceiling)
			}
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────

func sentKeysFor(f *fakeSender, id string) []string {
	var out []string
	for _, k := range f.sentKeys() {
		if k == "auth-email/"+id {
			out = append(out, k)
		}
	}
	return out
}

func bodiesFor(f *fakeSender, body string) []string {
	var out []string
	for _, b := range f.sentBodies() {
		if b == body {
			out = append(out, b)
		}
	}
	return out
}
