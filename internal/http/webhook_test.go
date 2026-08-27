package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcibernet/sesamo/internal/config"
	"github.com/jcibernet/sesamo/internal/email"
)

// These tests cover the outbox at the HTTP boundary: an end-user request
// must leave a queued, encrypted job behind (never a synchronous send),
// and a signed provider webhook must be the only thing that can move a
// job to delivered.

// testOutboxKeys is a fixed keyring so a test can decrypt what the
// handler queued — exactly the way another replica's worker would.
var testOutboxKeys = "http-test:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))

const testResendSecret = "whsec_c2VzYW1vLWh0dHAtdGVzdC13ZWJob29rLXNlY3JldA=="

// outboxHarness boots the server with a real keyring and webhook secret.
func outboxHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.EmailOutboxKeys = testOutboxKeys
		cfg.ResendWebhookSecret = testResendSecret
	})
}

// testOutbox builds the outbox a worker in another replica would use.
func testOutbox(t *testing.T, pool *pgxpool.Pool) *email.Outbox {
	t.Helper()
	kr, err := email.ParseKeyring(testOutboxKeys)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	return email.NewOutbox(pool, kr, testLogger(), nil)
}

// queuedJob is one row of email_outbox as tests read it.
type queuedJob struct {
	id                string
	status            string
	purpose           string
	recipient         string
	sender            string
	subject           string
	keyID             *string
	nonce             []byte
	ciphertext        []byte
	providerMessageID *string
	lastError         *string
	deliveredAt       *time.Time
	sendBefore        time.Time
}

func queuedJobs(t *testing.T, pool *pgxpool.Pool, recipient string) []queuedJob {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT id, status, purpose, recipient, sender, subject, key_id, nonce, ciphertext,
		       provider_message_id, last_error, delivered_at, send_before
		  FROM email_outbox WHERE recipient = $1 ORDER BY created_at`, recipient)
	if err != nil {
		t.Fatalf("query outbox: %v", err)
	}
	defer rows.Close()
	var out []queuedJob
	for rows.Next() {
		var j queuedJob
		if err := rows.Scan(&j.id, &j.status, &j.purpose, &j.recipient, &j.sender, &j.subject,
			&j.keyID, &j.nonce, &j.ciphertext, &j.providerMessageID, &j.lastError,
			&j.deliveredAt, &j.sendBefore); err != nil {
			t.Fatalf("scan outbox: %v", err)
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("outbox rows: %v", err)
	}
	return out
}

func jobsWithPurpose(jobs []queuedJob, purpose string) []queuedJob {
	var out []queuedJob
	for _, j := range jobs {
		if j.purpose == purpose {
			out = append(out, j)
		}
	}
	return out
}

// claimBody returns the decrypted body of the job queued for recipient
// under purpose, going through the real worker path (Claim decrypts).
// The purpose filter matters: signup already queued a verification mail
// for the same address.
func claimBody(t *testing.T, o *email.Outbox, recipient string, purpose email.Purpose) (email.Job, string) {
	t.Helper()
	jobs, err := o.Claim(context.Background(), "log", 50)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	for _, job := range jobs {
		if job.Message.To == recipient && job.Purpose == purpose {
			return job, job.Message.Body
		}
	}
	t.Fatalf("no claimable %s job for %s", purpose, recipient)
	return email.Job{}, ""
}

// ── enqueue instead of send ───────────────────────────────────────────

// A magic-link request must leave an encrypted job whose payload carries
// a link that actually works: the outbox replaces the synchronous send
// without weakening the flow.
func TestMagicLinkRequestQueuesEncryptedWorkingLink(t *testing.T) {
	h := outboxHarness(t)
	addr := uniqueEmail("outbox-magic")
	h.signup(addr, "correct-horse-1")

	c := h.client()
	res, body := h.postJSON(c, "/magiclink", url.Values{"email": {addr}})
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "magiclink_sent") {
		t.Fatalf("magiclink request: %d %s", res.StatusCode, body)
	}

	jobs := jobsWithPurpose(queuedJobs(t, h.pool, addr), "magiclink")
	if len(jobs) != 1 {
		t.Fatalf("queued magiclink jobs = %d, want 1", len(jobs))
	}
	job := jobs[0]
	if job.status != "pending" {
		t.Fatalf("status = %q, want pending", job.status)
	}
	if job.keyID == nil || *job.keyID != "http-test" {
		t.Fatalf("key_id = %v, want the configured keyring", job.keyID)
	}
	if len(job.nonce) == 0 || len(job.ciphertext) == 0 {
		t.Fatal("payload was not encrypted")
	}
	if strings.Contains(string(job.ciphertext), "token=") {
		t.Fatal("ciphertext exposes the link")
	}
	if job.sender != "auth@test.local" || job.subject == "" {
		t.Fatalf("envelope = %+v", job)
	}
	// send_before must precede the token's own expiry: an almost-dead
	// link is a broken product.
	var tokenExpiry time.Time
	if err := h.pool.QueryRow(context.Background(),
		`SELECT expires_at FROM one_time_tokens
		  WHERE user_id = (SELECT id FROM users WHERE email = $1) AND purpose = 'magiclink'`,
		addr).Scan(&tokenExpiry); err != nil {
		t.Fatalf("token expiry: %v", err)
	}
	if !job.sendBefore.Before(tokenExpiry) {
		t.Fatalf("send_before %v is not before the token expiry %v", job.sendBefore, tokenExpiry)
	}

	// The queued payload holds a real, spendable link.
	_, decrypted := claimBody(t, testOutbox(t, h.pool), addr, email.PurposeMagicLink)
	prefix := "http://127.0.0.1/magiclink/confirm?token="
	idx := strings.Index(decrypted, prefix)
	if idx < 0 {
		t.Fatal("queued body does not contain the magic link")
	}
	token := strings.TrimSpace(strings.SplitN(decrypted[idx+len(prefix):], "\n", 2)[0])
	if token == "" {
		t.Fatal("queued link carries no token")
	}

	confirm := h.client()
	res2, err := confirm.Get(h.srv.URL + "/magiclink/confirm?token=" + token + "&mode=json")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	payload, _ := io.ReadAll(res2.Body)
	if res2.StatusCode != http.StatusOK || !strings.Contains(string(payload), "authenticated") {
		t.Fatalf("queued link did not authenticate: %d %s", res2.StatusCode, payload)
	}
}

func TestSignupQueuesVerificationJob(t *testing.T) {
	h := outboxHarness(t)
	addr := uniqueEmail("outbox-signup")
	h.signup(addr, "correct-horse-2")

	jobs := jobsWithPurpose(queuedJobs(t, h.pool, addr), "verify")
	if len(jobs) != 1 {
		t.Fatalf("queued verify jobs = %d, want 1", len(jobs))
	}
	if jobs[0].status != "pending" {
		t.Fatalf("status = %q, want pending", jobs[0].status)
	}
	// 24h TTL minus the safety margin.
	if d := time.Until(jobs[0].sendBefore); d < 23*time.Hour || d > 24*time.Hour {
		t.Fatalf("send_before in %v, want just under 24h", d)
	}
	_, body := claimBody(t, testOutbox(t, h.pool), addr, email.PurposeVerify)
	if !strings.Contains(body, "/verify?token=") {
		t.Fatal("verification job does not carry a /verify link")
	}
}

// An unknown address must leave nothing behind: a queued row would be an
// enumeration oracle for anyone who can read the database.
func TestMagicLinkRequestForUnknownEmailQueuesNothing(t *testing.T) {
	h := outboxHarness(t)
	addr := uniqueEmail("outbox-ghost")

	c := h.client()
	res, body := h.postJSON(c, "/magiclink", url.Values{"email": {addr}})
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "magiclink_sent") {
		t.Fatalf("response must be identical for unknown accounts: %d %s", res.StatusCode, body)
	}
	if jobs := queuedJobs(t, h.pool, addr); len(jobs) != 0 {
		t.Fatalf("queued %d jobs for an unknown address", len(jobs))
	}
}

// Asking for a second link cancels the first job: only the newest link
// works, so the older mail would deliver a dead one.
func TestSecondRequestCancelsPendingJob(t *testing.T) {
	h := outboxHarness(t)
	addr := uniqueEmail("outbox-supersede")
	h.signup(addr, "correct-horse-3")

	c := h.client()
	for range 2 {
		res, body := h.postJSON(c, "/reset", url.Values{"email": {addr}})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("reset request: %d %s", res.StatusCode, body)
		}
	}

	jobs := jobsWithPurpose(queuedJobs(t, h.pool, addr), "reset")
	if len(jobs) != 2 {
		t.Fatalf("reset jobs = %d, want 2", len(jobs))
	}
	if jobs[0].status != "canceled" {
		t.Fatalf("first job status = %q, want canceled", jobs[0].status)
	}
	if jobs[0].ciphertext != nil {
		t.Fatal("canceled job kept its payload")
	}
	if jobs[1].status != "pending" {
		t.Fatalf("second job status = %q, want pending", jobs[1].status)
	}
}

// ── webhook ───────────────────────────────────────────────────────────

func postWebhook(t *testing.T, h *harness, secret, svixID string, ts time.Time, body []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/webhooks/resend", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(email.HeaderSvixID, svixID)
	req.Header.Set(email.HeaderSvixTimestamp, strconv.FormatInt(ts.Unix(), 10))
	if secret != "" {
		sig, err := email.SignSvix(secret, svixID, ts, body)
		if err != nil {
			t.Fatalf("SignSvix: %v", err)
		}
		req.Header.Set(email.HeaderSvixSignature, sig)
	} else {
		req.Header.Set(email.HeaderSvixSignature, "v1,Zm9yZ2VkLXNpZ25hdHVyZQ==")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// The endpoint only exists when an operator configured a secret: without
// one there is nothing to verify against, and accepting unauthenticated
// state changes would be worse than answering 503.
func TestResendWebhookUnconfiguredIsUnavailable(t *testing.T) {
	h := newHarness(t)
	res := postWebhook(t, h, "", "msg_unconfigured", time.Now(), []byte(`{"type":"email.delivered"}`))
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), codeForbidden) {
		t.Fatalf("body = %s", body)
	}
}

func TestResendWebhookRejectsBadSignature(t *testing.T) {
	h := outboxHarness(t)
	payload := []byte(`{"type":"email.delivered","data":{"email_id":"whatever"}}`)

	res := postWebhook(t, h, "", "msg_forged", time.Now(), payload)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), codeUnauthorized) {
		t.Fatalf("body = %s", body)
	}
	if n := countRows(t, h.pool, `SELECT count(*) FROM email_events WHERE svix_id = 'msg_forged'`); n != 0 {
		t.Fatal("a forged delivery must not be recorded")
	}
	// The rejection is observable without leaking anything.
	if !strings.Contains(metricsDump(t, h), email.MetricWebhookSignatureErrors) {
		t.Fatal("signature failures are not counted")
	}

	// A correctly signed but stale delivery is refused the same way.
	stale := postWebhook(t, h, testResendSecret, "msg_stale", time.Now().Add(-time.Hour), payload)
	defer stale.Body.Close()
	if stale.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale delivery status = %d, want 401", stale.StatusCode)
	}
}

// End to end: a request queues a job, the worker path accepts it, and a
// signed webhook is what turns "accepted by the API" into "delivered".
func TestResendWebhookMarksJobDelivered(t *testing.T) {
	h := outboxHarness(t)
	addr := uniqueEmail("outbox-webhook")
	h.signup(addr, "correct-horse-4")

	c := h.client()
	if res, body := h.postJSON(c, "/magiclink", url.Values{"email": {addr}}); res.StatusCode != http.StatusOK {
		t.Fatalf("magiclink request: %d %s", res.StatusCode, body)
	}

	o := testOutbox(t, h.pool)
	job, _ := claimBody(t, o, addr, email.PurposeMagicLink)
	const providerMessageID = "resend-http-e2e"
	if err := o.Finalize(context.Background(), job.ID, job.LeaseToken,
		email.Outcome{Kind: email.OutcomeAccepted, ProviderMessageID: providerMessageID}); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM email_events WHERE provider_message_id = $1`, providerMessageID)
	})

	payload := []byte(`{"type":"email.delivered","created_at":"` +
		time.Now().UTC().Format(time.RFC3339) +
		`","data":{"email_id":"` + providerMessageID + `"}}`)
	res := postWebhook(t, h, testResendSecret, "msg_delivered_e2e", time.Now(), payload)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("webhook: %d %s", res.StatusCode, body)
	}

	jobs := jobsWithPurpose(queuedJobs(t, h.pool, addr), "magiclink")
	if len(jobs) != 1 {
		t.Fatalf("magiclink jobs = %d", len(jobs))
	}
	if jobs[0].status != "delivered" {
		t.Fatalf("status = %q, want delivered", jobs[0].status)
	}
	if jobs[0].deliveredAt == nil {
		t.Fatal("delivered_at not stamped")
	}

	// Replay: same svix-id, answered 200 (the provider must stop
	// retrying) but stored and applied exactly once.
	replay := postWebhook(t, h, testResendSecret, "msg_delivered_e2e", time.Now(), payload)
	defer replay.Body.Close()
	if replay.StatusCode != http.StatusOK {
		t.Fatalf("replay status = %d, want 200", replay.StatusCode)
	}
	if n := countRows(t, h.pool,
		`SELECT count(*) FROM email_events WHERE svix_id = 'msg_delivered_e2e'`); n != 1 {
		t.Fatalf("stored events = %d, want 1", n)
	}

	// A complaint after delivery is terminal and stays visible.
	complaint := []byte(`{"type":"email.complained","data":{"email_id":"` + providerMessageID + `"}}`)
	cres := postWebhook(t, h, testResendSecret, "msg_complaint_e2e", time.Now(), complaint)
	defer cres.Body.Close()
	if cres.StatusCode != http.StatusOK {
		t.Fatalf("complaint status = %d", cres.StatusCode)
	}
	jobs = jobsWithPurpose(queuedJobs(t, h.pool, addr), "magiclink")
	if jobs[0].status != "failed" {
		t.Fatalf("status after complaint = %q, want failed", jobs[0].status)
	}
	if jobs[0].lastError == nil || *jobs[0].lastError != email.EventComplained {
		t.Fatalf("last_error = %v", jobs[0].lastError)
	}
	if jobs[0].deliveredAt == nil {
		t.Fatal("the delivery evidence must survive the complaint")
	}
}

// The webhook must not become an oracle: an unknown message id is
// accepted and stored, and answers exactly like a known one.
func TestResendWebhookUnknownMessageIDIsIndistinguishable(t *testing.T) {
	h := outboxHarness(t)
	payload := []byte(`{"type":"email.delivered","data":{"email_id":"not-ours"}}`)
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM email_events WHERE provider_message_id = 'not-ours'`)
	})

	res := postWebhook(t, h, testResendSecret, "msg_unknown_id", time.Now(), payload)
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("unknown id: %d %s", res.StatusCode, body)
	}
}

func TestResendWebhookRejectsMalformedEvent(t *testing.T) {
	h := outboxHarness(t)
	for _, payload := range [][]byte{
		[]byte(`not json`),
		[]byte(`{"type":"email.delivered"}`),         // no email id
		[]byte(`{"data":{"email_id":"x"}}`),          // no type
		[]byte(`{"type":"","data":{"email_id":""}}`), // empty both
	} {
		res := postWebhook(t, h, testResendSecret, "msg_malformed-"+strconv.Itoa(len(payload)), time.Now(), payload)
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("payload %s: status = %d, want 400 (%s)", payload, res.StatusCode, body)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────

func countRows(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func metricsDump(t *testing.T, h *harness) string {
	t.Helper()
	res, err := http.Get(h.srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return string(body)
}
