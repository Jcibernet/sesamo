// Package http wires the Sésamo HTTP surface using net/http +
// ServeMux (Go 1.22+ method-aware routing). No web framework.
package http

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jcibernet/sesamo/internal/config"
	"github.com/jcibernet/sesamo/internal/db"
	"github.com/jcibernet/sesamo/internal/email"
	"github.com/jcibernet/sesamo/internal/metrics"
	"github.com/jcibernet/sesamo/internal/oauth"
	"github.com/jcibernet/sesamo/internal/ratelimit"
	"github.com/jcibernet/sesamo/internal/session"
	"github.com/jcibernet/sesamo/internal/user"
)

// Server holds shared dependencies for all handlers.
type Server struct {
	cfg       *config.Config
	pool      *db.Pool
	log       *slog.Logger
	mux       *http.ServeMux
	sessions  *session.Store
	users     *user.Store
	tokens    *email.TokenStore
	mailer    email.Sender
	providers *oauth.Registry
	limiter   *ratelimit.Limiter
	metrics   *metrics.Registry
}

// NewServer builds the full handler tree.
func NewServer(cfg *config.Config, pool *db.Pool, log *slog.Logger) http.Handler {
	s := &Server{
		cfg:  cfg,
		pool: pool,
		log:  log,
		mux:  http.NewServeMux(),
		sessions: session.NewStore(pool, session.Config{
			Lifetime:                cfg.SessionLifetime,
			RollingRenewalThreshold: cfg.RollingRenewalThreshold,
		}),
		users:     user.NewStore(pool),
		tokens:    email.NewTokenStore(pool),
		mailer:    email.New(cfg.EmailProvider, cfg.EmailFrom, cfg.EmailAPIKey, log),
		providers: buildProviders(cfg, log),
		limiter:   ratelimit.New(pool),
		metrics:   metrics.New(),
	}

	s.registerOps()     // healthz, readyz, metrics
	s.registerEndUser() // /login, /logout, /signup, /reset, /auth/*
	s.registerService() // /v1/introspect, /v1/sessions/revoke
	s.registerAdmin()   // /v1/admin/*

	return s.withSecurityHeaders(s.withLogging(s.mux))
}

func buildProviders(cfg *config.Config, log *slog.Logger) *oauth.Registry {
	reg := oauth.NewRegistry()
	if cfg.Google.Enabled() {
		reg.Add(oauth.NewGoogle(cfg.Google.ClientID, cfg.Google.ClientSecret, cfg.Google.RedirectURI))
	}
	if cfg.GitHub.Enabled() {
		reg.Add(oauth.NewGitHub(cfg.GitHub.ClientID, cfg.GitHub.ClientSecret, cfg.GitHub.RedirectURI))
	}
	if cfg.Apple.Enabled() {
		ap, err := oauth.NewApple(cfg.Apple.ClientID, cfg.Apple.TeamID, cfg.Apple.KeyID,
			cfg.Apple.PrivateKey, cfg.Apple.RedirectURI)
		if err != nil {
			log.Error("apple provider disabled", "err", err)
		} else {
			reg.Add(ap)
		}
	}
	return reg
}

// registerOps wires liveness, readiness, and Prometheus metrics.
func (s *Server) registerOps() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.pool.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("db unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	s.mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(s.metrics.WritePrometheus()))
	})
}

// withSecurityHeaders sets conservative defaults on every response. The
// embedded UI uses no inline scripts, so a strict CSP is safe.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' "+s.cfg.ThemeCSSURL+"; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		if s.cfg.CookieSecure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// withLogging is a structured access log middleware that never logs
// secrets (no cookies, no auth headers, no bodies).
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		elapsed := time.Since(start)

		s.metrics.IncCounter("sesamo_http_requests_total")
		// Latency of the introspect hot path is the SLO we care about.
		if r.URL.Path == "/v1/introspect" {
			s.metrics.Observe("sesamo_introspect_duration_seconds", elapsed.Seconds())
		}

		s.log.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"dur_ms", elapsed.Milliseconds(),
			"ip", clientIP(r),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// clientIP extracts the best-effort client IP. We take the first hop of
// X-Forwarded-For when present (set by the trusted proxy/platform), else
// the remote address. This value is metadata only, never used for auth
// decisions, so spoofing it has no security impact beyond log accuracy.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
