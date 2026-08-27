package http

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/jcibernet/sesamo/internal/email"
)

// registerWebhooks wires provider callbacks. Public by necessity (the
// provider calls it unauthenticated), authenticated by signature.
func (s *Server) registerWebhooks() {
	s.mux.HandleFunc("POST /v1/webhooks/resend", s.handleResendWebhook)
}

// resendEvent is the subset of a Resend/Svix delivery we consume.
type resendEvent struct {
	Type      string `json:"type"`
	CreatedAt string `json:"created_at"`
	Data      struct {
		EmailID string `json:"email_id"`
	} `json:"data"`
}

// handleResendWebhook records provider delivery events.
//
// "Accepted by the API" and "delivered to the recipient's mail server"
// are different facts; this endpoint is where the second one enters the
// system. It authenticates the RAW body against the svix signature,
// deduplicates by svix-id, and correlates by provider message id.
//
// What it deliberately does NOT do: change the validity of any token, or
// tell the caller anything about an account. A signature failure and an
// unknown message id look the same from outside.
func (s *Server) handleResendWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ResendWebhookSecret == "" {
		// Not configured is not "unauthorized": there is no secret to
		// verify against, so the endpoint refuses to guess. Same shape as
		// an unconfigured admin surface.
		writeError(w, http.StatusServiceUnavailable, codeForbidden, "Webhook no configurado.")
		return
	}
	// Signature verification needs the exact bytes, so the body is read
	// once and never re-encoded. withBodyLimit already caps the size.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Cuerpo ilegible.")
		return
	}

	svixID, err := email.VerifySvix(s.cfg.ResendWebhookSecret, r.Header, body,
		time.Now(), email.WebhookTolerance)
	if err != nil {
		s.metrics.IncCounter(email.MetricWebhookSignatureErrors)
		// No body, no headers, no id: an unauthenticated caller must not
		// be able to write chosen data into the operator's logs.
		s.log.Warn("resend webhook rejected", "err", err, "req_id", requestID(r))
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "Firma inválida.")
		return
	}

	var ev resendEvent
	if err := json.Unmarshal(body, &ev); err != nil || ev.Type == "" || ev.Data.EmailID == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Evento inválido.")
		return
	}

	occurredAt := time.Now().UTC()
	if ev.CreatedAt != "" {
		// Resend sends RFC3339; a provider clock we cannot parse is not
		// worth a 400 — reception time keeps the ordering usable.
		if parsed, perr := time.Parse(time.RFC3339, ev.CreatedAt); perr == nil {
			occurredAt = parsed
		}
	}

	applied, err := s.outbox.RecordProviderEvent(r.Context(), svixID, ev.Data.EmailID, ev.Type, occurredAt)
	if err != nil {
		// A 500 makes the provider retry, which is what we want: the
		// event is not lost, and the svix-id dedup makes the retry safe.
		s.log.Error("record provider email event", "err", err, "event", ev.Type)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	if !applied {
		s.log.Info("resend webhook replay ignored", "event", ev.Type)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
