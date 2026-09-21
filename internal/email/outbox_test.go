package email

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ── shared test scaffolding ───────────────────────────────────────────

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeMetrics records emissions so tests can assert on observability
// without a registry.
type fakeMetrics struct {
	mu       sync.Mutex
	counters map[string]int
	gauges   map[string]float64
}

func newFakeMetrics() *fakeMetrics {
	return &fakeMetrics{counters: map[string]int{}, gauges: map[string]float64{}}
}

func (m *fakeMetrics) IncCounter(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name]++
}

func (m *fakeMetrics) SetGauge(name string, v float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gauges[name] = v
}

func (m *fakeMetrics) count(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name]
}

func (m *fakeMetrics) gauge(name string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gauges[name]
}

func newTestOutbox(t *testing.T, pool *pgxpool.Pool) (*Outbox, *Keyring, *fakeMetrics) {
	t.Helper()
	kr, err := ParseKeyring("test:" + testKey(42))
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	m := newFakeMetrics()
	return NewOutbox(pool, kr, discardLogger(), m), kr, m
}

const testLink = "https://auth.test.local/magiclink/confirm?token=RAW-TOKEN-VALUE"

// queueInput builds a deliverable job for user uid.
func queueInput(uid, tokenID string, purpose Purpose) QueueInput {
	return QueueInput{
		UserID:     uid,
		TokenID:    tokenID,
		To:         uid + "@test.local",
		From:       "auth@test.local",
		Subject:    "Tu enlace de acceso",
		Body:       "Tu enlace de acceso:\n\n" + testLink,
		Purpose:    purpose,
		Provider:   "resend",
		SendBefore: time.Now().Add(14 * time.Minute),
	}
}

// enqueue commits one job and returns its row id.
func enqueue(t *testing.T, o *Outbox, in QueueInput) string {
	t.Helper()
	ctx := context.Background()
	tx, err := o.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := o.QueueTx(ctx, tx, in); err != nil {
		t.Fatalf("QueueTx: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var id string
	if err := o.pool.QueryRow(ctx,
		`SELECT id FROM email_outbox
		  WHERE user_id = $1 AND purpose = $2 AND status = 'pending'
		  ORDER BY created_at DESC LIMIT 1`,
		in.UserID, string(in.Purpose)).Scan(&id); err != nil {
		t.Fatalf("read queued id: %v", err)
	}
	return id
}

// jobRow mirrors the columns tests assert on.
type jobRow struct {
	status            string
	keyID             *string
	nonce             []byte
	ciphertext        []byte
	attemptCount      int
	availableAt       time.Time
	leaseToken        *string
	leaseUntil        *time.Time
	providerMessageID *string
	lastError         *string
	acceptedAt        *time.Time
	deliveredAt       *time.Time
	failedAt          *time.Time
	canceledAt        *time.Time
	expiredAt         *time.Time
}

func readJob(t *testing.T, pool *pgxpool.Pool, id string) jobRow {
	t.Helper()
	var r jobRow
	err := pool.QueryRow(context.Background(), `
		SELECT status, key_id, nonce, ciphertext, attempt_count, available_at,
		       lease_token, lease_until, provider_message_id, last_error,
		       accepted_at, delivered_at, failed_at, canceled_at, expired_at
		  FROM email_outbox WHERE id = $1`, id).
		Scan(&r.status, &r.keyID, &r.nonce, &r.ciphertext, &r.attemptCount, &r.availableAt,
			&r.leaseToken, &r.leaseUntil, &r.providerMessageID, &r.lastError,
			&r.acceptedAt, &r.deliveredAt, &r.failedAt, &r.canceledAt, &r.expiredAt)
	if err != nil {
		t.Fatalf("read job %s: %v", id, err)
	}
	return r
}

// ── atomicity ─────────────────────────────────────────────────────────

// A rolled-back use case leaves neither the token nor the queued mail:
// no orphan link, no promise of an email nobody will send.
func TestQueueTxRollbackLeavesNoTokenAndNoJob(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	ts := NewTokenStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, tokenID, err := ts.IssueTx(ctx, tx, uid, PurposeMagicLink, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.QueueTx(ctx, tx, queueInput(uid, tokenID, PurposeMagicLink)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	if n := countRows(t, pool, `SELECT count(*) FROM one_time_tokens WHERE user_id = $1`, uid); n != 0 {
		t.Fatalf("tokens after rollback = %d, want 0", n)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM email_outbox WHERE user_id = $1`, uid); n != 0 {
		t.Fatalf("outbox rows after rollback = %d, want 0", n)
	}
}

func TestQueueTxCommitLeavesTokenAndJob(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	ts := NewTokenStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	token, tokenID, err := ts.IssueTx(ctx, tx, uid, PurposeReset, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	in := queueInput(uid, tokenID, PurposeReset)
	if err := o.QueueTx(ctx, tx, in); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	if n := countRows(t, pool, `SELECT count(*) FROM one_time_tokens WHERE user_id = $1`, uid); n != 1 {
		t.Fatalf("tokens = %d, want 1", n)
	}
	if n := countRows(t, pool,
		`SELECT count(*) FROM email_outbox WHERE user_id = $1 AND status = 'pending'`, uid); n != 1 {
		t.Fatalf("pending jobs = %d, want 1", n)
	}
	// The committed token is the one the queued link spends.
	if _, err := ts.Consume(ctx, token, PurposeReset); err != nil {
		t.Fatalf("committed token must be usable: %v", err)
	}
}

// ── payload confidentiality ───────────────────────────────────────────

func TestQueueTxEncryptsPayload(t *testing.T) {
	pool := testPool(t)
	o, kr, _ := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	in := queueInput(uid, "", PurposeMagicLink)
	id := enqueue(t, o, in)

	row := readJob(t, pool, id)
	if row.keyID == nil || *row.keyID != "test" {
		t.Fatalf("key_id = %v, want test", row.keyID)
	}
	if len(row.nonce) != nonceSize || len(row.ciphertext) == 0 {
		t.Fatalf("payload not sealed: nonce=%d ciphertext=%d", len(row.nonce), len(row.ciphertext))
	}
	if strings.Contains(string(row.ciphertext), "token=") ||
		strings.Contains(string(row.ciphertext), testLink) {
		t.Fatal("ciphertext contains the plaintext link")
	}
	// The whole row must not carry the link anywhere: envelope columns
	// are readable on purpose, the payload is not.
	var dump string
	if err := pool.QueryRow(context.Background(),
		`SELECT to_jsonb(email_outbox)::text FROM email_outbox WHERE id = $1`, id).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump, "RAW-TOKEN-VALUE") {
		t.Fatalf("row leaks the token in clear: %s", dump)
	}

	body, err := kr.Decrypt(*row.keyID, row.nonce, row.ciphertext,
		payloadAAD(id, in.Provider, string(in.Purpose)))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(body) != in.Body {
		t.Fatalf("decrypted body = %q", body)
	}
}

// ── supersession ──────────────────────────────────────────────────────

// Asking for a new link cancels the pending job of the previous one:
// only the newest link works, so delivering the old mail would ship a
// dead link (and a second one would look like a duplicate attack).
func TestQueueTxCancelsSupersededPendingJob(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	uid := makeUser(t, pool)

	first := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	second := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	if first == second {
		t.Fatal("second enqueue reused the first row")
	}

	old := readJob(t, pool, first)
	if old.status != "canceled" {
		t.Fatalf("superseded job status = %q, want canceled", old.status)
	}
	if old.canceledAt == nil {
		t.Fatal("canceled_at not stamped")
	}
	if old.ciphertext != nil || old.nonce != nil {
		t.Fatal("canceled job kept its payload")
	}
	if old.lastError == nil || *old.lastError != reasonSuperseded {
		t.Fatalf("last_error = %v, want %q", old.lastError, reasonSuperseded)
	}
	if readJob(t, pool, second).status != "pending" {
		t.Fatal("newest job must stay pending")
	}
	// A different purpose is a different mail: it must survive.
	other := enqueue(t, o, queueInput(uid, "", PurposeReset))
	enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	if got := readJob(t, pool, other).status; got != "pending" {
		t.Fatalf("reset job status = %q after a magiclink enqueue, want pending", got)
	}
}

// ── claiming ──────────────────────────────────────────────────────────

func TestClaimLeasesAndDecrypts(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	in := queueInput(uid, "", PurposeMagicLink)
	id := enqueue(t, o, in)

	jobs, err := o.Claim(context.Background(), "resend", 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	job, ok := findJob(jobs, id)
	if !ok {
		t.Fatal("queued job was not claimed")
	}
	if job.Message.Body != in.Body {
		t.Fatalf("claimed body = %q, want the decrypted payload", job.Message.Body)
	}
	if job.Message.To != in.To || job.Message.Subject != in.Subject {
		t.Fatalf("claimed envelope = %+v", job.Message)
	}
	if job.Attempt != 1 {
		t.Fatalf("attempt = %d, want 1", job.Attempt)
	}
	if job.IdempotencyKey() != "auth-email/"+id {
		t.Fatalf("idempotency key = %q", job.IdempotencyKey())
	}

	row := readJob(t, pool, id)
	if row.leaseToken == nil || *row.leaseToken != job.LeaseToken {
		t.Fatalf("lease token = %v, want %q", row.leaseToken, job.LeaseToken)
	}
	if row.leaseUntil == nil || !row.leaseUntil.After(time.Now()) {
		t.Fatalf("lease_until = %v, want a future instant", row.leaseUntil)
	}
	if row.attemptCount != 1 {
		t.Fatalf("attempt_count = %d, want 1", row.attemptCount)
	}

	// A live lease hides the job from every other claim.
	again, err := o.Claim(context.Background(), "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, taken := findJob(again, id); taken {
		t.Fatal("a leased job must not be claimable again")
	}
}

// Two workers claiming at the same time must partition the backlog:
// FOR UPDATE SKIP LOCKED is what keeps a job from being delivered twice.
func TestClaimConcurrentWorkersDoNotShareJobs(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)

	const jobs = 6
	ids := make(map[string]bool, jobs)
	for range jobs {
		uid := makeUser(t, pool)
		ids[enqueue(t, o, queueInput(uid, "", PurposeMagicLink))] = true
	}

	var wg sync.WaitGroup
	results := make([][]Job, 2)
	errs := make([]error, 2)
	start := make(chan struct{})
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = o.Claim(context.Background(), "resend", jobs)
		}(i)
	}
	close(start)
	wg.Wait()

	seen := map[string]int{}
	for i, batch := range results {
		if errs[i] != nil {
			t.Fatalf("claim %d: %v", i, errs[i])
		}
		for _, job := range batch {
			if ids[job.ID] {
				seen[job.ID]++
			}
		}
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("job %s claimed %d times by concurrent workers", id, n)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no job was claimed at all")
	}
}

// A worker that dies mid-send leaves a lease behind. Once it expires the
// job must come back — that is the crash-recovery path, and the stable
// idempotency key is what makes the replay safe.
func TestClaimRecoversJobWithExpiredLease(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	ctx := context.Background()

	first, err := o.Claim(ctx, "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	original, ok := findJob(first, id)
	if !ok {
		t.Fatal("job not claimed")
	}
	if _, err := pool.Exec(ctx,
		`UPDATE email_outbox SET lease_until = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	second, err := o.Claim(ctx, "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	recovered, ok := findJob(second, id)
	if !ok {
		t.Fatal("job with an expired lease was not recovered")
	}
	if recovered.Attempt != 2 {
		t.Fatalf("attempt = %d, want 2", recovered.Attempt)
	}
	if recovered.LeaseToken == original.LeaseToken {
		t.Fatal("recovery must mint a fresh lease token")
	}
	if recovered.IdempotencyKey() != original.IdempotencyKey() {
		t.Fatalf("idempotency key changed across recovery: %q != %q",
			recovered.IdempotencyKey(), original.IdempotencyKey())
	}

	// The stale owner can no longer write the outcome.
	err = o.Finalize(ctx, id, original.LeaseToken, Outcome{Kind: OutcomeAccepted, ProviderMessageID: "stale"})
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale finalize err = %v, want ErrLeaseLost", err)
	}
	if pmid := readJob(t, pool, id).providerMessageID; pmid != nil {
		t.Fatalf("stale worker overwrote the row: %v", pmid)
	}
}

func TestClaimExpiresJobPastSendWindow(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	in := queueInput(uid, "", PurposeMagicLink)
	in.SendBefore = time.Now().Add(-time.Second)
	id := enqueue(t, o, in)

	jobs, err := o.Claim(context.Background(), "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findJob(jobs, id); ok {
		t.Fatal("a job past send_before must never be delivered")
	}
	row := readJob(t, pool, id)
	if row.status != "expired" || row.expiredAt == nil {
		t.Fatalf("status = %q expired_at = %v", row.status, row.expiredAt)
	}
	if row.ciphertext != nil || row.nonce != nil {
		t.Fatal("expired job kept its payload")
	}
	if row.lastError == nil || *row.lastError != reasonSendWindowElapsed {
		t.Fatalf("last_error = %v", row.lastError)
	}
	if m.count(MetricExpired) != 1 {
		t.Fatalf("%s = %d, want 1", MetricExpired, m.count(MetricExpired))
	}
}

func TestClaimFailsJobAtAttemptCeiling(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`UPDATE email_outbox SET attempt_count = $2 WHERE id = $1`, id, MaxAttempts); err != nil {
		t.Fatal(err)
	}

	jobs, err := o.Claim(ctx, "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findJob(jobs, id); ok {
		t.Fatal("a job at the attempt ceiling must not be retried")
	}
	row := readJob(t, pool, id)
	if row.status != "failed" || row.failedAt == nil {
		t.Fatalf("status = %q failed_at = %v", row.status, row.failedAt)
	}
	if row.lastError == nil || *row.lastError != reasonMaxAttempts {
		t.Fatalf("last_error = %v", row.lastError)
	}
	if m.count(MetricFailed) != 1 {
		t.Fatalf("%s = %d, want 1", MetricFailed, m.count(MetricFailed))
	}
}

// The worker re-checks the link before handing it to a provider: a token
// already spent (or superseded) means the mail would carry a dead link.
func TestClaimCancelsJobWhoseTokenIsNoLongerLive(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	ts := NewTokenStore(pool)
	uid := makeUser(t, pool)
	ctx := context.Background()

	token, err := ts.Issue(ctx, uid, PurposeMagicLink, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var tokenID string
	if err := pool.QueryRow(ctx,
		`SELECT id FROM one_time_tokens WHERE user_id = $1 AND purpose = 'magiclink'`, uid).
		Scan(&tokenID); err != nil {
		t.Fatal(err)
	}
	id := enqueue(t, o, queueInput(uid, tokenID, PurposeMagicLink))
	if _, err := ts.Consume(ctx, token, PurposeMagicLink); err != nil {
		t.Fatal(err)
	}

	jobs, err := o.Claim(ctx, "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findJob(jobs, id); ok {
		t.Fatal("a job whose token is spent must not be sent")
	}
	row := readJob(t, pool, id)
	if row.status != "canceled" {
		t.Fatalf("status = %q, want canceled", row.status)
	}
	if row.lastError == nil || *row.lastError != reasonTokenInactive {
		t.Fatalf("last_error = %v", row.lastError)
	}
	if m.count(MetricCanceled) != 1 {
		t.Fatalf("%s = %d", MetricCanceled, m.count(MetricCanceled))
	}
}

// A payload that cannot be opened (key dropped from the keyring, row
// tampered with) is unusable forever: fail it terminally instead of
// spending twelve attempts on it.
func TestClaimRetiresUndecryptablePayload(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`UPDATE email_outbox SET ciphertext = decode('deadbeef', 'hex') WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	jobs, err := o.Claim(ctx, "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findJob(jobs, id); ok {
		t.Fatal("an undecryptable job must not be handed to the sender")
	}
	row := readJob(t, pool, id)
	if row.status != "failed" {
		t.Fatalf("status = %q, want failed", row.status)
	}
	if row.lastError == nil || *row.lastError != reasonDecryptFailed {
		t.Fatalf("last_error = %v", row.lastError)
	}
	if m.count(MetricDecryptErrors) != 1 {
		t.Fatalf("%s = %d, want 1", MetricDecryptErrors, m.count(MetricDecryptErrors))
	}
}

// ── finalize ──────────────────────────────────────────────────────────

func TestFinalizeAcceptedClearsPayloadAndRecordsProviderID(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	ctx := context.Background()

	jobs, err := o.Claim(ctx, "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	job, _ := findJob(jobs, id)
	if err := o.Finalize(ctx, id, job.LeaseToken,
		Outcome{Kind: OutcomeAccepted, ProviderMessageID: "resend-1"}); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	row := readJob(t, pool, id)
	if row.status != "accepted" || row.acceptedAt == nil {
		t.Fatalf("status = %q accepted_at = %v", row.status, row.acceptedAt)
	}
	if row.providerMessageID == nil || *row.providerMessageID != "resend-1" {
		t.Fatalf("provider_message_id = %v", row.providerMessageID)
	}
	if row.nonce != nil || row.ciphertext != nil {
		t.Fatal("accepted job must not keep the link payload")
	}
	if row.leaseToken != nil || row.leaseUntil != nil {
		t.Fatal("accepted job must release its lease")
	}
}

func TestFinalizeRetrySchedulesBackoffAndKeepsPending(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	ctx := context.Background()

	jobs, err := o.Claim(ctx, "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	job, _ := findJob(jobs, id)
	if err := o.Finalize(ctx, id, job.LeaseToken,
		Outcome{Kind: OutcomeRetry, Code: CodeProviderError, RetryIn: 90 * time.Second}); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	row := readJob(t, pool, id)
	if row.status != "pending" {
		t.Fatalf("status = %q, want pending", row.status)
	}
	if row.leaseToken != nil {
		t.Fatal("retry must release the lease")
	}
	if delay := time.Until(row.availableAt); delay < 60*time.Second || delay > 120*time.Second {
		t.Fatalf("available_at in %v, want ~90s", delay)
	}
	if row.lastError == nil || *row.lastError != CodeProviderError {
		t.Fatalf("last_error = %v", row.lastError)
	}
	// Still holding the payload: it has to be sent on the next attempt.
	if row.ciphertext == nil {
		t.Fatal("a retryable job lost its payload")
	}
	// And it is invisible until available_at.
	next, err := o.Claim(ctx, "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findJob(next, id); ok {
		t.Fatal("a backed-off job must not be claimed early")
	}
}

func TestFinalizeFailedClearsPayload(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	ctx := context.Background()

	jobs, err := o.Claim(ctx, "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	job, _ := findJob(jobs, id)
	if err := o.Finalize(ctx, id, job.LeaseToken,
		Outcome{Kind: OutcomeFailed, Code: CodeRejected}); err != nil {
		t.Fatal(err)
	}
	row := readJob(t, pool, id)
	if row.status != "failed" || row.failedAt == nil {
		t.Fatalf("status = %q failed_at = %v", row.status, row.failedAt)
	}
	if row.nonce != nil || row.ciphertext != nil {
		t.Fatal("terminal job must not keep the link payload")
	}
}

// ── provider events ───────────────────────────────────────────────────

// cleanupEvents removes the delivery events a test inserted (they are
// not owned by the user row, so they do not cascade).
func cleanupEvents(t *testing.T, pool *pgxpool.Pool, providerMessageID string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM email_events WHERE provider_message_id = $1`, providerMessageID)
	})
}

func TestRecordProviderEventDeduplicatesBySvixID(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := acceptJob(t, o, uid, "resend-dedup")
	cleanupEvents(t, pool, "resend-dedup")
	ctx := context.Background()

	applied, err := o.RecordProviderEvent(ctx, "msg_1", "resend-dedup", EventDelivered, time.Now())
	if err != nil || !applied {
		t.Fatalf("first delivery: applied=%v err=%v", applied, err)
	}
	applied, err = o.RecordProviderEvent(ctx, "msg_1", "resend-dedup", EventDelivered, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if applied {
		t.Fatal("a replayed svix-id must not be applied twice")
	}
	if n := countRows(t, pool,
		`SELECT count(*) FROM email_events WHERE provider_message_id = $1`, "resend-dedup"); n != 1 {
		t.Fatalf("stored events = %d, want 1", n)
	}
	if got := m.count(MetricDelivered); got != 1 {
		t.Fatalf("%s = %d, want 1", MetricDelivered, got)
	}
	if readJob(t, pool, id).status != "delivered" {
		t.Fatal("delivered event did not promote the job")
	}
}

// Provider events are unordered. A complaint stays visible even when a
// delivered event arrives after it: delivered_at records the delivery,
// but the operational status keeps reporting the failure — the row shows
// the full sequence instead of hiding the reputation problem.
func TestReduceEventOutOfOrderKeepsComplaintVisible(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := acceptJob(t, o, uid, "resend-order")
	cleanupEvents(t, pool, "resend-order")
	ctx := context.Background()

	complainedAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond)
	if _, err := o.RecordProviderEvent(ctx, "msg_complaint", "resend-order", EventComplained, complainedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecordProviderEvent(ctx, "msg_delivered", "resend-order", EventDelivered, time.Now()); err != nil {
		t.Fatal(err)
	}

	row := readJob(t, pool, id)
	if row.status != "failed" {
		t.Fatalf("status = %q, want failed (a late delivered must not erase a complaint)", row.status)
	}
	if row.lastError == nil || *row.lastError != EventComplained {
		t.Fatalf("last_error = %v, want %q", row.lastError, EventComplained)
	}
	if row.deliveredAt == nil {
		t.Fatal("delivered_at must still record the delivery evidence")
	}
	if row.failedAt == nil {
		t.Fatal("failed_at not stamped by the complaint")
	}

	// The reverse order lands on the same place: bounce after delivery.
	other := acceptJob(t, o, makeUser(t, pool), "resend-order-2")
	cleanupEvents(t, pool, "resend-order-2")
	if _, err := o.RecordProviderEvent(ctx, "msg_d2", "resend-order-2", EventDelivered, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := readJob(t, pool, other).status; got != "delivered" {
		t.Fatalf("status = %q, want delivered", got)
	}
	if _, err := o.RecordProviderEvent(ctx, "msg_b2", "resend-order-2", EventBounced, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := readJob(t, pool, other).status; got != "failed" {
		t.Fatalf("status = %q, want failed after a bounce", got)
	}
}

func TestReduceEventSentDoesNotOverwriteDelivered(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := acceptJob(t, o, uid, "resend-sent")
	cleanupEvents(t, pool, "resend-sent")
	ctx := context.Background()

	if _, err := o.RecordProviderEvent(ctx, "msg_d", "resend-sent", EventDelivered, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecordProviderEvent(ctx, "msg_s", "resend-sent", EventSent, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := readJob(t, pool, id).status; got != "delivered" {
		t.Fatalf("status = %q, want delivered (sent must not walk the state back)", got)
	}
}

func TestReduceEventDelayIsInformational(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := acceptJob(t, o, uid, "resend-delay")
	cleanupEvents(t, pool, "resend-delay")

	if _, err := o.RecordProviderEvent(context.Background(),
		"msg_delay", "resend-delay", EventDeliveryDelayed, time.Now()); err != nil {
		t.Fatal(err)
	}
	row := readJob(t, pool, id)
	if row.status != "accepted" {
		t.Fatalf("status = %q, want accepted", row.status)
	}
	if row.lastError == nil || *row.lastError != EventDeliveryDelayed {
		t.Fatalf("last_error = %v", row.lastError)
	}
}

// An event can beat our own accept update. It must be stored anyway and
// reconciled the moment the provider message id lands on the row.
func TestRecordProviderEventBeforeAcceptIsReconciled(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	cleanupEvents(t, pool, "resend-early")
	ctx := context.Background()

	applied, err := o.RecordProviderEvent(ctx, "msg_early", "resend-early", EventDelivered, time.Now())
	if err != nil || !applied {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
	if got := readJob(t, pool, id).status; got != "pending" {
		t.Fatalf("status = %q, want pending (the row does not know the id yet)", got)
	}

	jobs, err := o.Claim(ctx, "resend", 10)
	if err != nil {
		t.Fatal(err)
	}
	job, _ := findJob(jobs, id)
	if err := o.Finalize(ctx, id, job.LeaseToken,
		Outcome{Kind: OutcomeAccepted, ProviderMessageID: "resend-early"}); err != nil {
		t.Fatal(err)
	}
	row := readJob(t, pool, id)
	if row.status != "delivered" {
		t.Fatalf("status = %q, want delivered (early event not reconciled)", row.status)
	}
	if row.deliveredAt == nil {
		t.Fatal("delivered_at not reconciled")
	}
}

func TestReduceUnknownEventTypeDoesNotChangeStatus(t *testing.T) {
	pool := testPool(t)
	o, _, m := newTestOutbox(t, pool)
	uid := makeUser(t, pool)
	id := acceptJob(t, o, uid, "resend-unknown")
	cleanupEvents(t, pool, "resend-unknown")

	if _, err := o.RecordProviderEvent(context.Background(),
		"msg_unknown", "resend-unknown", "email.something_new", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := readJob(t, pool, id).status; got != "accepted" {
		t.Fatalf("status = %q, want accepted", got)
	}
	// Unknown types share one bucket, so a provider changelog cannot
	// explode metric cardinality.
	if got := m.count(MetricWebhookEvents + "_other"); got != 1 {
		t.Fatalf("other bucket = %d, want 1", got)
	}
}

// ── maintenance ───────────────────────────────────────────────────────

func TestPurgeFinishedKeepsPendingWork(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	ctx := context.Background()

	pending := enqueue(t, o, queueInput(makeUser(t, pool), "", PurposeMagicLink))
	done := acceptJob(t, o, makeUser(t, pool), "resend-purge")
	cleanupEvents(t, pool, "resend-purge")
	if _, err := o.RecordProviderEvent(ctx, "msg_purge", "resend-purge", EventDelivered, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE email_outbox SET updated_at = now() - interval '30 days' WHERE id = $1`, done); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE email_events SET received_at = now() - interval '30 days' WHERE svix_id = 'msg_purge'`); err != nil {
		t.Fatal(err)
	}

	n, err := o.PurgeFinished(ctx, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("PurgeFinished: %v", err)
	}
	if n < 2 {
		t.Fatalf("purged %d rows, want >= 2 (job + event)", n)
	}
	if countRows(t, pool, `SELECT count(*) FROM email_outbox WHERE id = $1`, done) != 0 {
		t.Fatal("finished job survived retention")
	}
	if countRows(t, pool, `SELECT count(*) FROM email_outbox WHERE id = $1`, pending) != 1 {
		t.Fatal("purge deleted a pending job")
	}
}

func TestQueueStatsReportsBacklog(t *testing.T) {
	pool := testPool(t)
	o, _, _ := newTestOutbox(t, pool)
	ctx := context.Background()

	before, err := o.QueueStats(ctx, "resend")
	if err != nil {
		t.Fatal(err)
	}
	id := enqueue(t, o, queueInput(makeUser(t, pool), "", PurposeMagicLink))
	if _, err := pool.Exec(ctx,
		`UPDATE email_outbox SET available_at = now() - interval '5 minutes' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	after, err := o.QueueStats(ctx, "resend")
	if err != nil {
		t.Fatal(err)
	}
	if after.Pending != before.Pending+1 {
		t.Fatalf("pending = %d, want %d", after.Pending, before.Pending+1)
	}
	if after.OldestPendingAge < 5*time.Minute {
		t.Fatalf("oldest pending age = %v, want >= 5m", after.OldestPendingAge)
	}
}

// ── helpers ───────────────────────────────────────────────────────────

func findJob(jobs []Job, id string) (Job, bool) {
	for _, j := range jobs {
		if j.ID == id {
			return j, true
		}
	}
	return Job{}, false
}

func countRows(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// acceptJob queues, claims and accepts a job under a known provider
// message id, which is the state every delivery-event test starts from.
func acceptJob(t *testing.T, o *Outbox, uid, providerMessageID string) string {
	t.Helper()
	ctx := context.Background()
	id := enqueue(t, o, queueInput(uid, "", PurposeMagicLink))
	jobs, err := o.Claim(ctx, "resend", 10)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	job, ok := findJob(jobs, id)
	if !ok {
		t.Fatal("job not claimed")
	}
	if err := o.Finalize(ctx, id, job.LeaseToken,
		Outcome{Kind: OutcomeAccepted, ProviderMessageID: providerMessageID}); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	return id
}
