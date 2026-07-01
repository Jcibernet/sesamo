// Package email provides a minimal pluggable sender for transactional
// auth emails (magic-link, password reset, verification). The default
// "log" provider prints the message to stdout for local dev.
package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// Message is a single outbound email.
type Message struct {
	To      string
	Subject string
	Body    string // plain text
}

// Sender delivers messages. Implementations must be safe for concurrent use.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// New builds a Sender from the provider name. Unknown providers fall
// back to the log sender so dev never hard-fails on email config.
func New(provider, from, apiKey string, log *slog.Logger) Sender {
	switch provider {
	case "resend":
		return &resendSender{from: from, apiKey: apiKey}
	case "postmark":
		return &postmarkSender{from: from, apiKey: apiKey}
	default:
		return &logSender{from: from, log: log}
	}
}

// logSender prints the email (including any link) to stdout. Dev only.
type logSender struct {
	from string
	log  *slog.Logger
}

func (s *logSender) Send(_ context.Context, msg Message) error {
	s.log.Info("email (dev log sender)",
		"from", s.from, "to", msg.To, "subject", msg.Subject, "body", msg.Body)
	return nil
}

type resendSender struct {
	from   string
	apiKey string
}

func (s *resendSender) Send(ctx context.Context, msg Message) error {
	payload, _ := json.Marshal(map[string]any{
		"from": s.from, "to": []string{msg.To},
		"subject": msg.Subject, "text": msg.Body,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.resend.com/emails", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("resend send: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("resend status %d", res.StatusCode)
	}
	return nil
}

type postmarkSender struct {
	from   string
	apiKey string
}

func (s *postmarkSender) Send(ctx context.Context, msg Message) error {
	payload, _ := json.Marshal(map[string]any{
		"From": s.from, "To": msg.To,
		"Subject": msg.Subject, "TextBody": msg.Body,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.postmarkapp.com/email", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("X-Postmark-Server-Token", s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("postmark send: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("postmark status %d", res.StatusCode)
	}
	return nil
}
