// Package email owns transactional auth mail (magic link, password
// reset, verification): one-time tokens, the durable outbox that queues
// a message in the caller's transaction, the worker that delivers it,
// and the provider adapters behind the Sender seam. The default "log"
// provider prints the message to stdout for local dev.
package email

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jcibernet/sesamo/internal/httpx"
)

// Message is a single outbound email.
type Message struct {
	To      string
	Subject string
	Body    string // plain text
}

// Receipt is what a provider returns when it accepts a message.
// ProviderMessageID is the correlation handle delivery webhooks use;
// accepted is not delivered.
type Receipt struct {
	ProviderMessageID string
}

// Sender delivers messages. Implementations must be safe for concurrent
// use.
//
// idempotencyKey is stable across retries of the same queued job, so a
// crash between the provider accepting the message and the local status
// update replays the exact same request instead of sending a second
// copy. Providers that do not support idempotency keys ignore it and
// rely on the weaker guarantee that a superseded link stops working.
type Sender interface {
	Send(ctx context.Context, msg Message, idempotencyKey string) (Receipt, error)
}

// SendError classifies a provider failure for the worker, which owns the
// retry policy and must never guess.
//
// Retryable covers transport failures, timeouts, 429, 5xx and the
// concurrent-idempotent-request conflict. Everything else is terminal:
// retrying a rejected recipient only burns the send_before window.
// RetryAfter carries the provider's own Retry-After when it sent one.
type SendError struct {
	Retryable  bool
	Code       string
	RetryAfter time.Duration
	err        error // transport cause, if any; never a response body
}

func (e *SendError) Error() string {
	kind := "terminal"
	if e.Retryable {
		kind = "retryable"
	}
	if e.err != nil {
		return fmt.Sprintf("email send %s (%s): %v", kind, e.Code, e.err)
	}
	return fmt.Sprintf("email send %s (%s)", kind, e.Code)
}

func (e *SendError) Unwrap() error { return e.err }

// Error codes reported by SendError. Fixed cardinality: they are safe as
// metric labels and as email_outbox.last_error values.
const (
	CodeTransport         = "transport"
	CodeRateLimited       = "rate_limited"
	CodeProviderError     = "provider_error"
	CodeConcurrentIdem    = "concurrent_idempotent_requests"
	CodeIdempotencyClash  = "invalid_idempotent_request"
	CodeRejected          = "rejected"
	CodeMalformedResponse = "malformed_response"
)

// emailResponseMaxBytes bounds what we read back from a provider. Both
// providers answer with a small JSON object; anything larger is either a
// proxy error page or an attempt to make us allocate.
const emailResponseMaxBytes = 8 << 10

// outboundHTTPClient bounds transactional-mail calls. A provider outage must
// consume at most this request's latency budget, never an HTTP handler.
var outboundHTTPClient = httpx.New(15 * time.Second)

const (
	resendEndpoint   = "https://api.resend.com/emails"
	postmarkEndpoint = "https://api.postmarkapp.com/email"
)

// New builds a Sender from the provider name. Unknown providers fall
// back to the log sender so dev never hard-fails on email config
// (production config rejects both an unknown provider and "log").
func New(provider, from, apiKey string, log *slog.Logger) Sender {
	switch provider {
	case "resend":
		return &resendSender{from: from, apiKey: apiKey, endpoint: resendEndpoint}
	case "postmark":
		return &postmarkSender{from: from, apiKey: apiKey, endpoint: postmarkEndpoint}
	default:
		return &logSender{from: from, log: log}
	}
}

// logSender prints the email (including any link) to stdout. Dev only:
// this is the one sender allowed to log a payload, and production
// configuration refuses to boot with it.
type logSender struct {
	from string
	log  *slog.Logger
}

func (s *logSender) Send(_ context.Context, msg Message, _ string) (Receipt, error) {
	s.log.Info("email (dev log sender)",
		"from", s.from, "to", msg.To, "subject", msg.Subject, "body", msg.Body)
	return Receipt{ProviderMessageID: "log"}, nil
}

type resendSender struct {
	from     string
	apiKey   string
	endpoint string
}

func (s *resendSender) Send(ctx context.Context, msg Message, idempotencyKey string) (Receipt, error) {
	payload, err := json.Marshal(map[string]any{
		"from": s.from, "to": []string{msg.To},
		"subject": msg.Subject, "text": msg.Body,
	})
	if err != nil {
		return Receipt{}, &SendError{Code: CodeRejected, err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(payload))
	if err != nil {
		return Receipt{}, &SendError{Code: CodeRejected, err: err}
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	// Resend keeps idempotency keys for 24h: the same key with the same
	// payload returns the original result instead of sending a copy.
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	res, err := outboundHTTPClient.Do(req)
	if err != nil {
		return Receipt{}, transportError(err)
	}
	defer res.Body.Close()
	body := readBounded(res.Body)

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		var ok struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &ok); err != nil || ok.ID == "" {
			// Accepted but unidentifiable: retrying under the same key is
			// safe (Resend replays the original), and without the id no
			// delivery webhook can ever be correlated to this job.
			return Receipt{}, &SendError{Retryable: true, Code: CodeMalformedResponse}
		}
		return Receipt{ProviderMessageID: ok.ID}, nil
	}
	return Receipt{}, classifyResend(res, body)
}

// classifyResend maps a non-2xx Resend response onto the retry policy.
func classifyResend(res *http.Response, body []byte) *SendError {
	// Resend errors: {"statusCode":N,"name":"...","message":"..."}.
	var apiErr struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &apiErr)
	retryAfter := retryAfterHeader(res.Header)

	switch {
	case res.StatusCode == http.StatusTooManyRequests:
		return &SendError{Retryable: true, Code: CodeRateLimited, RetryAfter: retryAfter}
	case res.StatusCode >= 500:
		return &SendError{Retryable: true, Code: CodeProviderError, RetryAfter: retryAfter}
	case res.StatusCode == http.StatusConflict &&
		strings.Contains(apiErr.Name, CodeConcurrentIdem):
		// The first attempt is still in flight at Resend. Backing off and
		// replaying the same key converges on its result.
		return &SendError{Retryable: true, Code: CodeConcurrentIdem, RetryAfter: retryAfter}
	case res.StatusCode == http.StatusConflict &&
		strings.Contains(apiErr.Name, CodeIdempotencyClash):
		// Same key, different payload: our own invariant is broken (the
		// key is derived from the immutable outbox id). Retrying cannot
		// fix it; this must reach an operator.
		return &SendError{Code: CodeIdempotencyClash}
	default:
		return &SendError{Code: providerCode(apiErr.Name, res.StatusCode)}
	}
}

// postmarkSender is the second adapter behind the same seam.
//
// Postmark has no idempotency-key header, so idempotencyKey is
// deliberately unused: a retry after an unobserved acceptance can
// deliver a second copy of the mail. What protects the user is the
// one-time-token contract — issuing a new link invalidates the previous
// one, and a duplicate of the SAME link is spendable exactly once. Resend
// is the provider covered by the stronger guarantee.
type postmarkSender struct {
	from     string
	apiKey   string
	endpoint string
}

func (s *postmarkSender) Send(ctx context.Context, msg Message, _ string) (Receipt, error) {
	payload, err := json.Marshal(map[string]any{
		"From": s.from, "To": msg.To,
		"Subject": msg.Subject, "TextBody": msg.Body,
	})
	if err != nil {
		return Receipt{}, &SendError{Code: CodeRejected, err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(payload))
	if err != nil {
		return Receipt{}, &SendError{Code: CodeRejected, err: err}
	}
	req.Header.Set("X-Postmark-Server-Token", s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := outboundHTTPClient.Do(req)
	if err != nil {
		return Receipt{}, transportError(err)
	}
	defer res.Body.Close()
	body := readBounded(res.Body)

	// Postmark answers with {"MessageID":"...","ErrorCode":0,...}.
	var api struct {
		MessageID string `json:"MessageID"`
		ErrorCode int    `json:"ErrorCode"`
	}
	_ = json.Unmarshal(body, &api)

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		if api.MessageID == "" {
			return Receipt{}, &SendError{Retryable: true, Code: CodeMalformedResponse}
		}
		return Receipt{ProviderMessageID: api.MessageID}, nil
	}
	retryAfter := retryAfterHeader(res.Header)
	switch {
	case res.StatusCode == http.StatusTooManyRequests:
		return Receipt{}, &SendError{Retryable: true, Code: CodeRateLimited, RetryAfter: retryAfter}
	case res.StatusCode >= 500:
		return Receipt{}, &SendError{Retryable: true, Code: CodeProviderError, RetryAfter: retryAfter}
	default:
		code := ""
		if api.ErrorCode != 0 {
			code = "postmark_" + strconv.Itoa(api.ErrorCode)
		}
		return Receipt{}, &SendError{Code: providerCode(code, res.StatusCode)}
	}
}

// transportError classifies a failure that never produced a response.
// Every one of them is retryable: we cannot know whether the provider
// saw the request, which is exactly what the idempotency key is for.
func transportError(err error) *SendError {
	code := CodeTransport
	if errors.Is(err, context.DeadlineExceeded) {
		code = "timeout"
	}
	return &SendError{Retryable: true, Code: code, err: err}
}

// providerCode prefers the provider's own error name, falling back to the
// status. Both are low-cardinality; neither carries payload text.
func providerCode(name string, status int) string {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "status_" + strconv.Itoa(status)
	}
	return name
}

// retryAfterHeader reads Retry-After in either accepted form (delta
// seconds or HTTP date). An unparseable value yields 0, which the worker
// reads as "use your own backoff".
func retryAfterHeader(h http.Header) time.Duration {
	raw := strings.TrimSpace(h.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if at, err := http.ParseTime(raw); err == nil {
		if d := time.Until(at); d > 0 {
			return d
		}
	}
	return 0
}

func readBounded(r io.Reader) []byte {
	body, _ := io.ReadAll(io.LimitReader(r, emailResponseMaxBytes))
	return body
}
