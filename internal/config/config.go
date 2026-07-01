// Package config loads all runtime configuration from environment
// variables only — no config file, no config library (os.Getenv).
package config

import (
	"fmt"
	"os"
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

	Google OAuthProviderConfig
	GitHub OAuthProviderConfig
	Apple  AppleConfig

	EmailProvider string
	EmailFrom     string
	EmailAPIKey   string

	ThemeCSSURL string

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
		EmailProvider: getenv("SESAMO_EMAIL_PROVIDER", "log"),
		EmailFrom:     getenv("SESAMO_EMAIL_FROM", "auth@localhost"),
		EmailAPIKey:   getenv("SESAMO_EMAIL_API_KEY", ""),
		ThemeCSSURL:   getenv("SESAMO_THEME_CSS_URL", ""),
		OIDCEnabled:   getbool("SESAMO_OIDC_ENABLED", false),
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
