package email

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests exercise the classification the worker's retry policy
// depends on. Nothing here reaches the network: every case is a local
// httptest server speaking the provider's response shape.

func TestResendSendSuccessReturnsReceipt(t *testing.T) {
	var gotAuth, gotIdem, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotIdem = r.Header.Get("Idempotency-Key")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"a1b2c3"}`))
	}))
	defer srv.Close()

	s := &resendSender{from: "auth@test.local", apiKey: "re_test", endpoint: srv.URL}
	receipt, err := s.Send(context.Background(),
		Message{To: "user@test.local", Subject: "Asunto", Body: "cuerpo"}, "auth-email/job-1")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if receipt.ProviderMessageID != "a1b2c3" {
		t.Fatalf("provider message id = %q", receipt.ProviderMessageID)
	}
	if gotAuth != "Bearer re_test" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotIdem != "auth-email/job-1" {
		t.Fatalf("idempotency key = %q", gotIdem)
	}
	var payload struct {
		From    string   `json:"from"`
		To      []string `json:"to"`
		Subject string   `json:"subject"`
		Text    string   `json:"text"`
	}
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if payload.From != "auth@test.local" || len(payload.To) != 1 || payload.To[0] != "user@test.local" ||
		payload.Subject != "Asunto" || payload.Text != "cuerpo" {
		t.Fatalf("unexpected payload: %s", gotBody)
	}
}

func TestResendSendClassification(t *testing.T) {
	cases := []struct {
		name          string
		status        int
		body          string
		retryAfter    string
		wantRetryable bool
		wantCode      string
		wantRetryIn   time.Duration
	}{
		{name: "rate limited", status: 429, body: `{"name":"rate_limit_exceeded"}`,
			retryAfter: "7", wantRetryable: true, wantCode: CodeRateLimited, wantRetryIn: 7 * time.Second},
		{name: "server error", status: 500, body: `{"name":"internal_server_error"}`,
			wantRetryable: true, wantCode: CodeProviderError},
		{name: "bad gateway", status: 502, body: `nginx`,
			wantRetryable: true, wantCode: CodeProviderError},
		{name: "concurrent idempotent", status: 409, body: `{"name":"concurrent_idempotent_requests"}`,
			wantRetryable: true, wantCode: CodeConcurrentIdem},
		{name: "idempotency clash", status: 409, body: `{"name":"invalid_idempotent_request"}`,
			wantRetryable: false, wantCode: CodeIdempotencyClash},
		{name: "validation error", status: 422, body: `{"name":"validation_error","message":"To is invalid"}`,
			wantRetryable: false, wantCode: "validation_error"},
		{name: "unauthenticated", status: 401, body: `{}`,
			wantRetryable: false, wantCode: "status_401"},
		{name: "accepted without id", status: 200, body: `{}`,
			wantRetryable: true, wantCode: CodeMalformedResponse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			s := &resendSender{from: "auth@test.local", apiKey: "k", endpoint: srv.URL}
			_, err := s.Send(context.Background(), Message{To: "u@test.local"}, "auth-email/job")
			var sendErr *SendError
			if !errors.As(err, &sendErr) {
				t.Fatalf("err = %v, want *SendError", err)
			}
			if sendErr.Retryable != tc.wantRetryable {
				t.Fatalf("retryable = %v, want %v", sendErr.Retryable, tc.wantRetryable)
			}
			if sendErr.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", sendErr.Code, tc.wantCode)
			}
			if sendErr.RetryAfter != tc.wantRetryIn {
				t.Fatalf("retry after = %v, want %v", sendErr.RetryAfter, tc.wantRetryIn)
			}
			// The error text reaches logs and last_error: it must not
			// carry a provider message.
			if strings.Contains(sendErr.Error(), "To is invalid") {
				t.Fatalf("error leaks provider message: %v", sendErr)
			}
		})
	}
}

// A dead endpoint produces a transport failure, which is always
// retryable: we cannot know whether the provider saw the request.
func TestResendTransportFailureIsRetryable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	s := &resendSender{from: "auth@test.local", apiKey: "k", endpoint: url}
	_, err := s.Send(context.Background(), Message{To: "u@test.local"}, "auth-email/job")
	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Fatalf("err = %v, want *SendError", err)
	}
	if !sendErr.Retryable || sendErr.Code != CodeTransport {
		t.Fatalf("got retryable=%v code=%q", sendErr.Retryable, sendErr.Code)
	}
}

func TestResendRetryAfterHTTPDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", time.Now().Add(90*time.Second).UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	s := &resendSender{from: "auth@test.local", apiKey: "k", endpoint: srv.URL}
	_, err := s.Send(context.Background(), Message{To: "u@test.local"}, "auth-email/job")
	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Fatalf("err = %v", err)
	}
	if sendErr.RetryAfter < 30*time.Second || sendErr.RetryAfter > 90*time.Second {
		t.Fatalf("retry after = %v, want ~90s", sendErr.RetryAfter)
	}
}

// The provider must never see more than the bounded body we read back;
// an oversized error page cannot make the adapter allocate freely.
func TestResendResponseIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"name":"` + strings.Repeat("x", 32<<10) + `"}`))
	}))
	defer srv.Close()

	s := &resendSender{from: "auth@test.local", apiKey: "k", endpoint: srv.URL}
	_, err := s.Send(context.Background(), Message{To: "u@test.local"}, "auth-email/job")
	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Fatalf("err = %v", err)
	}
	// The truncated body cannot parse as JSON, so the status is the code —
	// and the giant name never becomes a metric label.
	if sendErr.Code != "status_400" {
		t.Fatalf("code = %q, want status_400", sendErr.Code)
	}
}

func TestPostmarkSendSuccessAndClassification(t *testing.T) {
	var gotToken, gotIdem string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Postmark-Server-Token")
		gotIdem = r.Header.Get("Idempotency-Key")
		_, _ = w.Write([]byte(`{"MessageID":"pm-1","ErrorCode":0}`))
	}))
	defer srv.Close()

	s := &postmarkSender{from: "auth@test.local", apiKey: "pm-token", endpoint: srv.URL}
	receipt, err := s.Send(context.Background(), Message{To: "u@test.local"}, "auth-email/job")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if receipt.ProviderMessageID != "pm-1" {
		t.Fatalf("provider message id = %q", receipt.ProviderMessageID)
	}
	if gotToken != "pm-token" {
		t.Fatalf("token header = %q", gotToken)
	}
	// Documented gap: Postmark has no idempotency key, so we must not
	// pretend to send one.
	if gotIdem != "" {
		t.Fatalf("unexpected Idempotency-Key %q", gotIdem)
	}

	for _, tc := range []struct {
		status        int
		body          string
		wantRetryable bool
		wantCode      string
	}{
		{503, `{}`, true, CodeProviderError},
		{429, `{}`, true, CodeRateLimited},
		{422, `{"ErrorCode":406,"Message":"inactive recipient"}`, false, "postmark_406"},
		{400, `{}`, false, "status_400"},
		{200, `{"MessageID":""}`, true, CodeMalformedResponse},
	} {
		t.Run(strconv.Itoa(tc.status)+"_"+tc.wantCode, func(t *testing.T) {
			bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer bad.Close()
			s := &postmarkSender{from: "auth@test.local", apiKey: "k", endpoint: bad.URL}
			_, err := s.Send(context.Background(), Message{To: "u@test.local"}, "auth-email/job")
			var sendErr *SendError
			if !errors.As(err, &sendErr) {
				t.Fatalf("err = %v, want *SendError", err)
			}
			if sendErr.Retryable != tc.wantRetryable || sendErr.Code != tc.wantCode {
				t.Fatalf("got retryable=%v code=%q, want %v %q",
					sendErr.Retryable, sendErr.Code, tc.wantRetryable, tc.wantCode)
			}
		})
	}
}

func TestNewSelectsProvider(t *testing.T) {
	log := discardLogger()
	if _, ok := New("resend", "f", "k", log).(*resendSender); !ok {
		t.Fatal("resend must build the Resend adapter")
	}
	if _, ok := New("postmark", "f", "k", log).(*postmarkSender); !ok {
		t.Fatal("postmark must build the Postmark adapter")
	}
	for _, provider := range []string{"log", "", "typo"} {
		if _, ok := New(provider, "f", "k", log).(*logSender); !ok {
			t.Fatalf("provider %q must fall back to the log sender", provider)
		}
	}
	// The dev sender still reports a receipt, so the outbox can mark the
	// job accepted instead of retrying forever in local development.
	receipt, err := New("log", "f", "", log).Send(context.Background(), Message{}, "auth-email/x")
	if err != nil || receipt.ProviderMessageID != "log" {
		t.Fatalf("log sender receipt = %+v, err = %v", receipt, err)
	}
}
