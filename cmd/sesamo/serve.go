package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jcibernet/sesamo/internal/audit"
	"github.com/jcibernet/sesamo/internal/config"
	"github.com/jcibernet/sesamo/internal/db"
	"github.com/jcibernet/sesamo/internal/email"
	httpapi "github.com/jcibernet/sesamo/internal/http"
	"github.com/jcibernet/sesamo/internal/ratelimit"
	"github.com/jcibernet/sesamo/internal/session"
)

const (
	// Bound every phase after headers too: ReadHeaderTimeout alone does not
	// stop a slow POST that trickles fewer than maxBodyBytes forever.
	serverReadHeaderTimeout = 10 * time.Second
	serverReadTimeout       = 30 * time.Second
	serverWriteTimeout      = 30 * time.Second
	serverIdleTimeout       = 120 * time.Second

	// The worker stops claiming on cancellation but may finish one send
	// (20s) and its durable Finalize (5s). Keep the process and pool alive
	// long enough to record that acceptance before exit.
	shutdownTimeout = 30 * time.Second
)

// serve wires the HTTP handler and runs the server until ctx is done.
func serve(ctx context.Context, cfg *config.Config, pool *db.Pool, log *slog.Logger) error {
	api, err := httpapi.NewServer(cfg, pool, log)
	if err != nil {
		return err
	}
	// The email worker runs in-process, one per replica: jobs are
	// partitioned by lease, so scaling replicas scales delivery without
	// duplicating mail. It shares the server's outbox and metrics.
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		api.EmailWorker().Run(workerCtx)
	}()
	go runMaintenance(ctx, cfg, pool, log, api.EmailOutbox())

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "base_url", cfg.BaseURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case <-ctx.Done():
		httpShutdownCtx, cancelHTTP := context.WithTimeout(context.Background(), shutdownTimeout)

		// Stop accepting HTTP work first, then drain the one email delivery
		// that can be in flight. Closing the pool before the worker exits
		// loses provider acceptance and causes a duplicate after lease
		// recovery (notably with Postmark, which has no idempotency key).
		shutdownErr := srv.Shutdown(httpShutdownCtx)
		cancelHTTP()

		workerShutdownCtx, cancelWorkerWait := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancelWorkerWait()
		stopWorker()
		select {
		case <-workerDone:
		case <-workerShutdownCtx.Done():
			return workerShutdownCtx.Err()
		}
		if errors.Is(shutdownErr, context.DeadlineExceeded) {
			log.Warn("HTTP shutdown grace elapsed")
			return nil
		}
		return shutdownErr
	case err := <-errc:
		stopWorker()
		return err
	}
}

// maintenanceInterval is how often expired state is purged. Expired
// sessions are also deleted opportunistically on Validate, so this only
// needs to catch abandoned rows; hourly keeps tables tight without
// measurable load.
const maintenanceInterval = time.Hour

// outboxRetention is how long a finished email job (and its delivery
// events) survives. This table is an execution log, not evidence:
// audit_log keeps the business record of a reset or a magic link, so a
// short window is enough to diagnose a delivery incident.
const outboxRetention = 7 * 24 * time.Hour

// runMaintenance periodically deletes rows that can no longer affect
// behavior: expired sessions, dead one-time tokens, rate-limit buckets
// that have fully refilled, finished email-outbox jobs past retention,
// and (only when SESAMO_AUDIT_RETENTION_DAYS is set) audit rows past
// retention. Unbounded growth of any of these is a denial-of-service
// vector (disk, index bloat) — see THREAT_MODEL.md.
func runMaintenance(ctx context.Context, cfg *config.Config, pool *db.Pool, log *slog.Logger, outbox *email.Outbox) {
	sessions := session.NewStore(pool, session.Config{
		Lifetime:                cfg.SessionLifetime,
		RollingRenewalThreshold: cfg.RollingRenewalThreshold,
		MaxLifetime:             cfg.SessionMaxLifetime,
	})
	tokens := email.NewTokenStore(pool)
	limiter := ratelimit.New(pool)
	auditor := audit.New(pool, log, cfg.AuditStrict)

	t := time.NewTicker(maintenanceInterval)
	defer t.Stop()
	for {
		mctx, cancel := context.WithTimeout(ctx, time.Minute)
		ns, err := sessions.PurgeExpired(mctx)
		if err != nil {
			log.Warn("purge sessions", "err", err)
		}
		nt, err := tokens.PurgeExpired(mctx)
		if err != nil {
			log.Warn("purge tokens", "err", err)
		}
		nb, err := limiter.PurgeStale(mctx, 24*time.Hour)
		if err != nil {
			log.Warn("purge rate limit buckets", "err", err)
		}
		var na int64
		if cfg.AuditRetention > 0 {
			na, err = auditor.PurgeOlderThan(mctx, cfg.AuditRetention)
			if err != nil {
				log.Warn("purge audit log", "err", err)
			}
		}
		no, err := outbox.PurgeFinished(mctx, outboxRetention)
		if err != nil {
			log.Warn("purge email outbox", "err", err)
		}
		cancel()
		if ns+nt+nb+na+no > 0 {
			log.Info("maintenance purge", "sessions", ns, "tokens", nt, "buckets", nb,
				"audit", na, "email_outbox", no)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
