// Package config loads all runtime configuration from environment
// variables only — no config file, no config library (os.Getenv).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-resolved runtime configuration.
type Config struct {
	// Env selects the deployment profile. EnvDevelopment (default) keeps
	// the permissive local defaults — http, insecure cookie, stdout
	// mailer, plaintext Postgres — that make local dev painless.
	// EnvProduction turns every one of them into a boot failure
	// (validateProduction): a misconfigured auth server that starts is
	// worse than one that refuses to.
	Env string

	DatabaseURL string
	BaseURL     string
	ListenAddr  string

	CookieName      string
	CookieSecure    bool
	CookieDomain    string
	SessionLifetime time.Duration
	// SessionMaxLifetime is the absolute ceiling on a session's age,
	// counted from creation: rolling renewal may extend expires_at up to
	// this bound and no further. Without it an active client — or a
	// stolen cookie replayed once per renewal window — lives forever.
	SessionMaxLifetime      time.Duration
	RollingRenewalThreshold time.Duration

	ServiceToken string
	AdminAPIKey  string

	// TrustProxy controls whether X-Forwarded-For is honored for client
	// IP extraction. It MUST be false (default) when Sésamo is directly
	// reachable, because the client IP keys the login rate limiter: a
	// spoofed XFF would mint fresh buckets per request and bypass the
	// per-IP brute-force limit. Set true only behind a proxy that
	// overwrites (not appends to) the header.
	TrustProxy bool

	// AuditStrict flips audit writes from best-effort to mandatory: a
	// failed audit_log insert aborts the auth operation it would have
	// evidenced (no evidence, no action). Default false — availability
	// of the auth path wins; enable for compliance-grade deployments.
	AuditStrict bool

	// AuditRetention bounds audit_log growth: rows older than this are
	// deleted by the hourly maintenance job. Zero (default) keeps the
	// audit log forever — retention is a compliance decision the
	// operator must make explicitly, so we never silently destroy
	// evidence.
	AuditRetention time.Duration

	// RedirectOrigins is the exact-match allowlist of external origins a
	// post-login/post-logout redirect may target. Empty (default) keeps
	// the pre-existing behavior: only internal paths are honored. Origins
	// are compared as literal scheme://host[:port] strings — no wildcard,
	// no subdomain inference, no default-port equivalence. That rigidity
	// is the point: an open redirect on an auth server converts every
	// phishing email into a credible login link.
	RedirectOrigins []string

	// Signup selects the registration policy: SignupPublic (default,
	// current behavior) or SignupDisabled — POST /signup creates nothing
	// and OAuth login refuses to create a brand-new account while still
	// admitting identities that resolve to an existing user.
	Signup string

	Google OAuthProviderConfig
	GitHub OAuthProviderConfig
	Apple  AppleConfig

	EmailProvider string
	EmailFrom     string
	EmailAPIKey   string

	ThemeCSSURL string
	Brand       BrandConfig

	OIDCEnabled bool
}

// Signup policy values for Config.Signup.
const (
	SignupPublic   = "public"
	SignupDisabled = "disabled"
)

// Env values for Config.Env.
const (
	EnvDevelopment = "development"
	EnvProduction  = "production"
)

// defaultSessionMaxLifetimeDays is the absolute session cap applied when
// SESAMO_SESSION_MAX_LIFETIME_DAYS is unset (or nonsense in dev).
const defaultSessionMaxLifetimeDays = 90

// productionSecretMinLen is the minimum length of the service token and
// the admin API key in production. Both are bearer secrets guarding
// introspection and user administration; the generated values the README
// recommends (openssl rand -base64 32) clear this, "changeme" does not.
const productionSecretMinLen = 32

// productionSSLModes are the sslmode values that actually encrypt the
// Postgres connection. "prefer" and "allow" negotiate down to plaintext
// without a word, which is why an explicit mode is required.
var productionSSLModes = map[string]bool{
	"require":     true,
	"verify-ca":   true,
	"verify-full": true,
}

// OAuthProviderConfig holds the standard client_id/secret/redirect set.
type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// Enabled reports whether the provider has the minimum config to run.
func (p OAuthProviderConfig) Enabled() bool {
	return p.ClientID != "" && p.ClientSecret != "" && p.RedirectURI != ""
}

// AppleConfig holds Apple's JWT-client-assertion specific fields.
type AppleConfig struct {
	ClientID    string
	TeamID      string
	KeyID       string
	PrivateKey  string
	RedirectURI string
}

// Enabled reports whether Apple Sign In has the minimum config.
func (a AppleConfig) Enabled() bool {
	return a.ClientID != "" && a.TeamID != "" && a.KeyID != "" &&
		a.PrivateKey != "" && a.RedirectURI != ""
}

// Load reads configuration from the environment, applying defaults and
// validating that required fields are present.
func Load() (*Config, error) {
	c := &Config{
		Env:           getenv("SESAMO_ENV", EnvDevelopment),
		DatabaseURL:   getenv("SESAMO_DATABASE_URL", ""),
		BaseURL:       getenv("SESAMO_BASE_URL", "http://localhost:7777"),
		ListenAddr:    getenv("SESAMO_LISTEN_ADDR", ":7777"),
		CookieName:    getenv("SESAMO_COOKIE_NAME", "sid"),
		CookieSecure:  getbool("SESAMO_COOKIE_SECURE", false),
		CookieDomain:  getenv("SESAMO_COOKIE_DOMAIN", ""),
		ServiceToken:  getenv("SESAMO_SERVICE_TOKEN", ""),
		AdminAPIKey:   getenv("SESAMO_ADMIN_API_KEY", ""),
		TrustProxy:    getbool("SESAMO_TRUST_PROXY", false),
		AuditStrict:   getbool("SESAMO_AUDIT_STRICT", false),
		EmailProvider: getenv("SESAMO_EMAIL_PROVIDER", "log"),
		EmailFrom:     getenv("SESAMO_EMAIL_FROM", "auth@localhost"),
		EmailAPIKey:   getenv("SESAMO_EMAIL_API_KEY", ""),
		ThemeCSSURL:   getenv("SESAMO_THEME_CSS_URL", ""),
		Brand: BrandConfig{
			LogoURL:      getenv("SESAMO_BRAND_LOGO_URL", ""),
			PrimaryColor: getenv("SESAMO_BRAND_PRIMARY_COLOR", ""),
			PageBG:       getenv("SESAMO_BRAND_PAGE_BG", ""),
			FontURL:      getenv("SESAMO_BRAND_FONT_URL", ""),
		},
		OIDCEnabled: getbool("SESAMO_OIDC_ENABLED", false),
		Signup:      getenv("SESAMO_SIGNUP", SignupPublic),
		Google: OAuthProviderConfig{
			ClientID:     getenv("SESAMO_GOOGLE_CLIENT_ID", ""),
			ClientSecret: getenv("SESAMO_GOOGLE_CLIENT_SECRET", ""),
			RedirectURI:  getenv("SESAMO_GOOGLE_REDIRECT_URI", ""),
		},
		GitHub: OAuthProviderConfig{
			ClientID:     getenv("SESAMO_GITHUB_CLIENT_ID", ""),
			ClientSecret: getenv("SESAMO_GITHUB_CLIENT_SECRET", ""),
			RedirectURI:  getenv("SESAMO_GITHUB_REDIRECT_URI", ""),
		},
		Apple: AppleConfig{
			ClientID:    getenv("SESAMO_APPLE_CLIENT_ID", ""),
			TeamID:      getenv("SESAMO_APPLE_TEAM_ID", ""),
			KeyID:       getenv("SESAMO_APPLE_KEY_ID", ""),
			PrivateKey:  getenv("SESAMO_APPLE_PRIVATE_KEY", ""),
			RedirectURI: getenv("SESAMO_APPLE_REDIRECT_URI", ""),
		},
	}
	if c.Env != EnvDevelopment && c.Env != EnvProduction {
		return nil, fmt.Errorf("SESAMO_ENV: must be %q or %q, got %q",
			EnvDevelopment, EnvProduction, c.Env)
	}
	prod := c.Env == EnvProduction

	// Integer env vars stay dev-silent (a typo keeps the default) but
	// production collects the parse failures: silently running with a
	// 30-day session when the operator asked for 1 is a security bug.
	var intErrs []error
	days, err := getint("SESAMO_SESSION_LIFETIME_DAYS", 30)
	if err != nil {
		intErrs = append(intErrs, err)
	}
	c.SessionLifetime = time.Duration(days) * 24 * time.Hour
	mins, err := getint("SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES", 15)
	if err != nil {
		intErrs = append(intErrs, err)
	}
	c.RollingRenewalThreshold = time.Duration(mins) * time.Minute
	maxDays, err := getint("SESAMO_SESSION_MAX_LIFETIME_DAYS", defaultSessionMaxLifetimeDays)
	if err != nil {
		intErrs = append(intErrs, err)
	}
	if !prod && maxDays <= 0 {
		// The cap is a safety net, not a dev-time obstacle: locally an
		// absent or nonsense value falls back to the default instead of
		// producing sessions that expire the instant they are created.
		maxDays = defaultSessionMaxLifetimeDays
	}
	c.SessionMaxLifetime = time.Duration(maxDays) * 24 * time.Hour
	// Retention keeps its historical best-effort parsing: 0 (keep
	// forever) is the safe reading of a broken value.
	if rd, _ := getint("SESAMO_AUDIT_RETENTION_DAYS", 0); rd > 0 {
		c.AuditRetention = time.Duration(rd) * 24 * time.Hour
	}

	origins, err := parseRedirectOrigins(os.Getenv("SESAMO_REDIRECT_ORIGINS"))
	if err != nil {
		return nil, err
	}
	c.RedirectOrigins = origins

	if c.Signup != SignupPublic && c.Signup != SignupDisabled {
		return nil, fmt.Errorf("SESAMO_SIGNUP: must be %q or %q, got %q",
			SignupPublic, SignupDisabled, c.Signup)
	}

	if err := c.Brand.validate(); err != nil {
		return nil, err
	}

	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("SESAMO_DATABASE_URL is required")
	}

	// Session invariant, both environments: a cap shorter than one
	// session lifetime would expire sessions before their first renewal.
	if c.SessionMaxLifetime < c.SessionLifetime {
		return nil, fmt.Errorf(
			"SESAMO_SESSION_MAX_LIFETIME_DAYS (%s) must be >= SESAMO_SESSION_LIFETIME_DAYS (%s)",
			c.SessionMaxLifetime, c.SessionLifetime)
	}

	if prod {
		if probs := c.validateProduction(intErrs); len(probs) > 0 {
			return nil, fmt.Errorf("SESAMO_ENV=production: %w", errors.Join(probs...))
		}
	}
	return c, nil
}

// parseRedirectOrigins validates a comma-separated origin list. Each
// entry must be a bare absolute http(s) origin — host required, no
// userinfo, no path, no query, no fragment — and is normalized to
// lowercase scheme://host[:port] (hosts are case-insensitive, RFC 3986).
// Boot fails loudly on anything else: a silently
// dropped origin would surface later as a mysterious redirect to "/".
func parseRedirectOrigins(raw string) ([]string, error) {
	var origins []string
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		u, err := url.Parse(entry)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("SESAMO_REDIRECT_ORIGINS: %q must be an absolute http(s) origin", entry)
		}
		if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("SESAMO_REDIRECT_ORIGINS: %q must be a bare origin without path, query, fragment, or userinfo", entry)
		}
		origins = append(origins, u.Scheme+"://"+strings.ToLower(u.Host))
	}
	return origins, nil
}

// envField pairs an env var name with its resolved value so error
// messages can name the variable the operator has to fix.
type envField struct {
	name  string
	value string
}

// validateProduction returns every production invariant this Config
// violates. All of them are collected before returning: an operator
// promoting a dev deployment fixes one list instead of restarting into
// the next surprise. intErrs carries the integer parse failures
// development tolerates.
func (c *Config) validateProduction(intErrs []error) []error {
	probs := append([]error(nil), intErrs...)

	if !strings.HasPrefix(c.BaseURL, "https://") {
		probs = append(probs, fmt.Errorf(
			"SESAMO_BASE_URL: must start with https:// in production, got %q", c.BaseURL))
	}
	if !c.CookieSecure {
		probs = append(probs, errors.New(
			"SESAMO_COOKIE_SECURE: must be true in production (a session cookie sent over http is a session handed over)"))
	}

	for _, f := range []envField{
		{"SESAMO_SERVICE_TOKEN", c.ServiceToken},
		{"SESAMO_ADMIN_API_KEY", c.AdminAPIKey},
	} {
		switch {
		case f.value == "":
			probs = append(probs, fmt.Errorf("%s: required in production", f.name))
		case len(f.value) < productionSecretMinLen:
			probs = append(probs, fmt.Errorf("%s: must be at least %d characters in production, got %d",
				f.name, productionSecretMinLen, len(f.value)))
		}
	}
	if c.ServiceToken != "" && c.ServiceToken == c.AdminAPIKey {
		probs = append(probs, errors.New(
			"SESAMO_SERVICE_TOKEN and SESAMO_ADMIN_API_KEY: must differ (otherwise every introspect caller also holds admin rights)"))
	}

	if c.EmailProvider != "resend" && c.EmailProvider != "postmark" {
		probs = append(probs, fmt.Errorf(
			"SESAMO_EMAIL_PROVIDER: must be \"resend\" or \"postmark\" in production, got %q (the \"log\" provider prints reset links to stdout instead of sending them)",
			c.EmailProvider))
	}
	if c.EmailAPIKey == "" {
		probs = append(probs, errors.New("SESAMO_EMAIL_API_KEY: required in production"))
	}
	if c.EmailFrom == "" || strings.Contains(strings.ToLower(c.EmailFrom), "localhost") {
		probs = append(probs, fmt.Errorf(
			"SESAMO_EMAIL_FROM: must be a deliverable sender address in production, got %q", c.EmailFrom))
	}

	probs = appendNonNil(probs,
		checkOAuthBlock("google", []envField{
			{"SESAMO_GOOGLE_CLIENT_ID", c.Google.ClientID},
			{"SESAMO_GOOGLE_CLIENT_SECRET", c.Google.ClientSecret},
			{"SESAMO_GOOGLE_REDIRECT_URI", c.Google.RedirectURI},
		}),
		checkOAuthBlock("github", []envField{
			{"SESAMO_GITHUB_CLIENT_ID", c.GitHub.ClientID},
			{"SESAMO_GITHUB_CLIENT_SECRET", c.GitHub.ClientSecret},
			{"SESAMO_GITHUB_REDIRECT_URI", c.GitHub.RedirectURI},
		}),
		checkOAuthBlock("apple", []envField{
			{"SESAMO_APPLE_CLIENT_ID", c.Apple.ClientID},
			{"SESAMO_APPLE_TEAM_ID", c.Apple.TeamID},
			{"SESAMO_APPLE_KEY_ID", c.Apple.KeyID},
			{"SESAMO_APPLE_PRIVATE_KEY", c.Apple.PrivateKey},
			{"SESAMO_APPLE_REDIRECT_URI", c.Apple.RedirectURI},
		}),
	)

	switch mode := dsnSSLMode(c.DatabaseURL); {
	case mode == "":
		probs = append(probs, errors.New(
			"SESAMO_DATABASE_URL: sslmode is required in production (use require, verify-ca, or verify-full); without it libpq/pgx default to \"prefer\", which silently falls back to plaintext"))
	case !productionSSLModes[mode]:
		probs = append(probs, fmt.Errorf(
			"SESAMO_DATABASE_URL: sslmode=%s does not guarantee an encrypted connection; use require, verify-ca, or verify-full", mode))
	}

	if c.SessionLifetime <= 0 {
		probs = append(probs, errors.New("SESAMO_SESSION_LIFETIME_DAYS: must be > 0 in production"))
	}
	if c.RollingRenewalThreshold <= 0 {
		probs = append(probs, errors.New("SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES: must be > 0 in production"))
	}
	if c.SessionMaxLifetime <= 0 {
		probs = append(probs, errors.New("SESAMO_SESSION_MAX_LIFETIME_DAYS: must be > 0 in production"))
	}
	return probs
}

// appendNonNil appends only the non-nil errors, keeping the call sites
// that produce one-error-or-nil checks free of nil guards.
func appendNonNil(dst []error, errs ...error) []error {
	for _, err := range errs {
		if err != nil {
			dst = append(dst, err)
		}
	}
	return dst
}

// checkOAuthBlock enforces all-or-nothing on one provider's env block.
// A half-configured provider is simply not registered at runtime
// (Enabled() is false), so in production it shows up as a login button
// that vanished — or worse, an OAuth flow the operator believes is live.
// Boot loudly instead of guessing intent.
func checkOAuthBlock(provider string, fields []envField) error {
	var set, missing []string
	for _, f := range fields {
		if f.value == "" {
			missing = append(missing, f.name)
		} else {
			set = append(set, f.name)
		}
	}
	if len(set) == 0 || len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("OAuth %s is partially configured: %s set, %s missing (set all of them or none)",
		provider, strings.Join(set, ", "), strings.Join(missing, ", "))
}

// dsnSSLMode extracts the sslmode parameter from a Postgres DSN, in both
// the URL and the keyword/value form pgx accepts. We parse it by hand
// instead of using pgconn.ParseConfig because that function resolves the
// mode into a *tls.Config and applies its own default, so the one thing
// we need to know — whether the operator stated a mode at all — is no
// longer observable. PGSSLMODE is honored as a fallback because pgx
// honors it too. Returns "" when no mode is stated anywhere.
func dsnSSLMode(dsn string) string {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		if u, err := url.Parse(dsn); err == nil {
			if mode := strings.TrimSpace(u.Query().Get("sslmode")); mode != "" {
				return mode
			}
		}
	} else {
		// Keyword/value DSN: "host=db port=5432 sslmode=require".
		for _, pair := range strings.Fields(dsn) {
			if k, v, ok := strings.Cut(pair, "="); ok && k == "sslmode" {
				return strings.TrimSpace(v)
			}
		}
	}
	return strings.TrimSpace(os.Getenv("PGSSLMODE"))
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func getbool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// getint reads an integer env var. An unset var yields def with no
// error; a malformed one yields def AND an error, so development can
// keep booting on a typo while production refuses to.
func getint(key string, def int) (int, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def, fmt.Errorf("%s: %q is not an integer", key, v)
	}
	return n, nil
}

// BrandConfig is the no-code branding layer (Auth0 "basic branding"
// equivalent): logo, primary color, page background, and font — applied
// via a generated /ui/brand.css without the operator writing CSS. For
// full control SESAMO_THEME_CSS_URL still overrides everything (it
// loads last). Precedence: theme.css < brand.css < SESAMO_THEME_CSS_URL.
type BrandConfig struct {
	LogoURL      string // SESAMO_BRAND_LOGO_URL: absolute URL, SVG recommended
	PrimaryColor string // SESAMO_BRAND_PRIMARY_COLOR: CSS color value
	PageBG       string // SESAMO_BRAND_PAGE_BG: CSS color/gradient value
	FontURL      string // SESAMO_BRAND_FONT_URL: woff/woff2 file URL
}

// Active reports whether any branding knob is set.
func (b BrandConfig) Active() bool {
	return b.LogoURL != "" || b.PrimaryColor != "" || b.PageBG != "" || b.FontURL != ""
}

// cssValueRe accepts hex colors, named colors, and functional notation
// (rgb/hsl/color-mix/linear-gradient...). It rejects every character
// that could terminate a declaration or smuggle a URL into the
// generated stylesheet (; { } / \ " ' etc.) — the values land verbatim
// inside brand.css, so this is an injection boundary even though env
// vars are operator-controlled.
var cssValueRe = regexp.MustCompile(`^[A-Za-z0-9#(),.%\s-]+$`)

// validate fails boot on values that could break or escape brand.css /
// the CSP header. Broken branding should be loud, not silently ugly.
func (b BrandConfig) validate() error {
	for name, v := range map[string]string{
		"SESAMO_BRAND_PRIMARY_COLOR": b.PrimaryColor,
		"SESAMO_BRAND_PAGE_BG":       b.PageBG,
	} {
		if v != "" && !cssValueRe.MatchString(v) {
			return fmt.Errorf("%s: invalid CSS value %q", name, v)
		}
	}
	for name, v := range map[string]string{
		"SESAMO_BRAND_LOGO_URL": b.LogoURL,
		"SESAMO_BRAND_FONT_URL": b.FontURL,
	} {
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%s: must be an absolute http(s) URL, got %q", name, v)
		}
	}
	return nil
}

// Origin returns scheme://host for an absolute URL, or "" — used to
// extend the CSP (img-src / font-src) with exactly the brand hosts.
func Origin(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
