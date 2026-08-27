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

	"github.com/jcibernet/sesamo/internal/audit"
	"github.com/jcibernet/sesamo/internal/config"
	"github.com/jcibernet/sesamo/internal/db"
	"github.com/jcibernet/sesamo/internal/email"
	"github.com/jcibernet/sesamo/internal/metrics"
	"github.com/jcibernet/sesamo/internal/oauth"
	"github.com/jcibernet/sesamo/internal/ratelimit"
	"github.com/jcibernet/sesamo/internal/session"
	"github.com/jcibernet/sesamo/internal/ui"
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
	audit     *audit.Logger
	brandCSS  []byte // generated /ui/brand.css (nil when branding unset)
	csp       string // precomputed Content-Security-Policy value
}

// NewServer builds the full handler tree. It returns an error when a
// configured dependency cannot be constructed — an OAuth provider the
// operator asked for, above all: starting without it would silently
// serve a login page missing a login method.
func NewServer(cfg *config.Config, pool *db.Pool, log *slog.Logger) (http.Handler, error) {
	providers, err := buildProviders(cfg)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:  cfg,
		pool: pool,
		log:  log,
		mux:  http.NewServeMux(),
		sessions: session.NewStore(pool, session.Config{
			Lifetime:                cfg.SessionLifetime,
			RollingRenewalThreshold: cfg.RollingRenewalThreshold,
			MaxLifetime:             cfg.SessionMaxLifetime,
		}),
		users:     user.NewStore(pool),
		tokens:    email.NewTokenStore(pool),
		mailer:    email.New(cfg.EmailProvider, cfg.EmailFrom, cfg.EmailAPIKey, log),
		providers: providers,
		limiter:   ratelimit.New(pool),
		metrics:   metrics.New(),
		audit:     audit.New(pool, log, cfg.AuditStrict),
		brandCSS:  ui.BrandCSS(ui.BrandInput(cfg.Brand)),
	}
	s.csp = buildCSP(cfg)

	s.registerOps()     // healthz, readyz, metrics
	s.registerEndUser() // /login, /logout, /signup, /reset, /auth/*
	s.registerService() // /v1/introspect, /v1/sessions/revoke
	s.registerAdmin()   // /v1/admin/*

	return s.withSecurityHeaders(s.withLogging(s.withBodyLimit(s.mux))), nil
}

// buildProviders registers exactly the OAuth providers the operator
// configured. A configured-but-unconstructable provider (Apple with an
// unparseable PEM) is a boot failure, not a warning: logging and
// continuing produced a server whose Apple button 404s while the
// operator's logs scrolled past the one line that said why.
func buildProviders(cfg *config.Config) (*oauth.Registry, error) {
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
			return nil, err
		}
		reg.Add(ap)
	}
	return reg, nil
}

// buildCSP assembles the Content-Security-Policy once at startup. The
// base is strict ('self', no inline scripts); the ONLY relaxations are
// the exact operator-configured origins: the override stylesheet
// (style-src), the brand logo host (img-src), and the brand font host
// (font-src). Never wildcards.
func buildCSP(cfg *config.Config) string {
	style := "style-src 'self'"
	if cfg.ThemeCSSURL != "" {
		style += " " + cfg.ThemeCSSURL
	}
	img := "img-src 'self' data:"
	if o := config.Origin(cfg.Brand.LogoURL); o != "" {
		img += " " + o
	}
	font := "font-src 'self'"
	if o := config.Origin(cfg.Brand.FontURL); o != "" {
		font += " " + o
	}
	return "default-src 'self'; " + style + "; " + img + "; " + font +
		"; form-action 'self'; frame-ancestors 'none'"
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
		h.Set("Content-Security-Policy", s.csp)
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
			"ip", s.clientIP(r),
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

// maxBodyBytes caps request bodies. Every legitimate body Sésamo accepts
// is a small form or JSON payload (credentials, a token); 64 KiB is two
// orders of magnitude above any of them. This bounds memory per request
// against slow-POST / oversized-body abuse (STRIDE: denial of service).
const maxBodyBytes = 64 << 10

// withBodyLimit wraps every request body in http.MaxBytesReader. Form
// parsing past the cap fails, so handlers see empty values and return
// their normal validation errors.
func (s *Server) withBodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// recordAudit writes an audit event for the current request. In strict
// mode (SESAMO_AUDIT_STRICT) a failed write responds 500 and returns
// false: the caller MUST stop — no evidence, no action. In best-effort
// mode it always returns true. Anti-enumeration endpoints whose response
// must stay identical for existing and unknown identities must NOT use
// this helper (a 500 would become an existence oracle); they check
// Record's error themselves and degrade silently.
func (s *Server) recordAudit(w http.ResponseWriter, r *http.Request, e audit.Event, actorUser string, detail map[string]any) bool {
	if err := s.audit.Record(r.Context(), e, actorUser, s.clientIP(r), detail); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return false
	}
	return true
}

// clientIP extracts the client IP. X-Forwarded-For is honored ONLY when
// SESAMO_TRUST_PROXY is set, because this value keys the per-IP login
// rate limiter: honoring a client-controlled header would let an
// attacker mint a fresh bucket per request and bypass the brute-force
// limit (and grow rate_limit_buckets without bound). Behind a trusted
// proxy that overwrites the header, the first hop is the real client.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			return strings.TrimSpace(first)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
