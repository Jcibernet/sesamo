// Package audit writes append-only security events to the audit_log
// table (STRIDE: repudiation). By default recording is best-effort: a
// failed write is logged via slog and never fails the request that
// triggered it — availability of the auth path wins over audit
// completeness. With SESAMO_AUDIT_STRICT the tradeoff flips for
// compliance-grade deployments: Record surfaces the write error and
// handlers refuse to complete the operation without evidence.
//
// The introspection hot path is deliberately NOT audited: it runs on
// every protected request and would dominate the table while providing
// no forensic value beyond the access log.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Event names follow "noun.verb" so they can be filtered by prefix.
type Event string

const (
	LoginSuccess       Event = "login.success"
	LoginFailed        Event = "login.failed"
	Signup             Event = "signup"
	Logout             Event = "logout"
	EmailVerified      Event = "email.verified"
	ResetRequested     Event = "reset.requested"
	ResetCompleted     Event = "reset.completed"
	MagicLinkRequest   Event = "magiclink.requested"
	SessionRevoked     Event = "session.revoked"
	SessionsRevokedAll Event = "sessions.revoked_all"
)

// writeTimeout bounds the audit insert so a slow database cannot stall
// the response that triggered the event.
const writeTimeout = 5 * time.Second

// Logger records events. Zero-allocation on the request path is not a
// goal here; auth events are low-frequency by construction (rate limits
// cap them far below any interesting throughput).
type Logger struct {
	pool   *pgxpool.Pool
	log    *slog.Logger
	strict bool
}

// New constructs a Logger. strict controls whether Record surfaces
// write failures to callers (see package doc).
func New(pool *pgxpool.Pool, log *slog.Logger, strict bool) *Logger {
	return &Logger{pool: pool, log: log, strict: strict}
}

// Record inserts one audit row. actorUser is the affected/acting user id
// ("" -> NULL). ip is stored only when it parses as a valid IP. detail
// must never contain secrets: no tokens, no hashes, no passwords.
// The insert survives request-context cancellation (the client hanging
// up must not erase the evidence).
//
// The returned error is always nil in best-effort mode; in strict mode
// it is the write/marshal failure and the caller MUST abort the
// operation it was about to evidence.
func (l *Logger) Record(ctx context.Context, event Event, actorUser, ip string, detail map[string]any) error {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()

	var actor any
	if actorUser != "" {
		actor = actorUser
	}
	var ipArg any
	if p := net.ParseIP(ip); p != nil {
		ipArg = p.String()
	}
	detailJSON := []byte("{}")
	if len(detail) > 0 {
		b, err := json.Marshal(detail)
		if err != nil {
			l.log.Warn("audit detail marshal failed", "event", event, "err", err)
			if l.strict {
				return err
			}
		} else {
			detailJSON = b
		}
	}

	if _, err := l.pool.Exec(dctx, `
		INSERT INTO audit_log (actor_user, event, ip, detail)
		VALUES ($1, $2, $3::inet, $4::jsonb)`,
		actor, string(event), ipArg, string(detailJSON)); err != nil {
		l.log.Warn("audit write failed", "event", event, "err", err)
		if l.strict {
			return err
		}
	}
	return nil
}
