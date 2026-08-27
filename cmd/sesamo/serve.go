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

// serve wires the HTTP handler and runs the server until ctx is done.
func serve(ctx context.Context, cfg *config.Config, pool *db.Pool, log *slog.Logger) error {
	handler, err := httpapi.NewServer(cfg, pool, log)
	if err != nil {
		return err
	}
	go runMaintenance(ctx, cfg, pool, log)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errc:
		return err
	}
}

// maintenanceInterval is how often expired state is purged. Expired
// sessions are also deleted opportunistically on Validate, so this only
// needs to catch abandoned rows; hourly keeps tables tight without
// measurable load.
const maintenanceInterval = time.Hour

// runMaintenance periodically deletes rows that can no longer affect
// behavior: expired sessions, dead one-time tokens, rate-limit buckets
// that have fully refilled, and (only when SESAMO_AUDIT_RETENTION_DAYS
// is set) audit rows past retention. Unbounded growth of any of these
// is a denial-of-service vector (disk, index bloat) — see THREAT_MODEL.md.
func runMaintenance(ctx context.Context, cfg *config.Config, pool *db.Pool, log *slog.Logger) {
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
		cancel()
		if ns+nt+nb+na > 0 {
			log.Info("maintenance purge", "sessions", ns, "tokens", nt, "buckets", nb, "audit", na)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
