// Package config loads all runtime configuration from environment
// variables only — no config file, no config library (os.Getenv).
package config

import (
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
	DatabaseURL string
	BaseURL     string
	ListenAddr  string

	CookieName              string
	CookieSecure            bool
	CookieDomain            string
	SessionLifetime         time.Duration
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

	days := getint("SESAMO_SESSION_LIFETIME_DAYS", 30)
	c.SessionLifetime = time.Duration(days) * 24 * time.Hour
	mins := getint("SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES", 15)
	c.RollingRenewalThreshold = time.Duration(mins) * time.Minute

	if err := c.Brand.validate(); err != nil {
		return nil, err
	}

	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("SESAMO_DATABASE_URL is required")
	}
	return c, nil
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

func getint(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
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
