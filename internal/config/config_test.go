package config

import (
	"strings"
	"testing"
	"time"
)

// TestLoad_BrandValidation exercises BrandConfig validation as it is
// actually reached in production: through config.Load() reading
// SESAMO_BRAND_* env vars, not by calling the unexported validate()
// method directly.
func TestLoad_BrandValidation(t *testing.T) {
	cases := []struct {
		name         string
		logoURL      string
		primaryColor string
		pageBG       string
		fontURL      string
		wantErr      bool
	}{
		{
			name:         "valid hex color passes",
			primaryColor: "#e11d48",
			wantErr:      false,
		},
		{
			name:    "valid gradient passes",
			pageBG:  "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
			wantErr: false,
		},
		{
			name:         "color with semicolon rejected",
			primaryColor: "red; background: url(evil)",
			wantErr:      true,
		},
		{
			name:    "color with brace rejected",
			pageBG:  "red}body{color:red",
			wantErr: true,
		},
		{
			name:    "javascript scheme logo rejected",
			logoURL: "javascript:alert(1)",
			wantErr: true,
		},
		{
			name:    "relative logo url rejected",
			logoURL: "/logo.svg",
			wantErr: true,
		},
		{
			name:    "absolute https logo url passes",
			logoURL: "https://cdn.example.com/logo.svg",
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SESAMO_DATABASE_URL", "postgres://sesamo:sesamo@localhost:5999/sesamo_dummy?sslmode=disable")
			t.Setenv("SESAMO_BRAND_LOGO_URL", tc.logoURL)
			t.Setenv("SESAMO_BRAND_PRIMARY_COLOR", tc.primaryColor)
			t.Setenv("SESAMO_BRAND_PAGE_BG", tc.pageBG)
			t.Setenv("SESAMO_BRAND_FONT_URL", tc.fontURL)

			cfg, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Load() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if cfg.Brand.LogoURL != tc.logoURL {
				t.Errorf("Brand.LogoURL = %q, want %q", cfg.Brand.LogoURL, tc.logoURL)
			}
			if cfg.Brand.PrimaryColor != tc.primaryColor {
				t.Errorf("Brand.PrimaryColor = %q, want %q", cfg.Brand.PrimaryColor, tc.primaryColor)
			}
			if cfg.Brand.PageBG != tc.pageBG {
				t.Errorf("Brand.PageBG = %q, want %q", cfg.Brand.PageBG, tc.pageBG)
			}
		})
	}
}

// TestOrigin covers the scheme://host extraction used to widen the CSP
// to exactly the operator's brand hosts.
func TestOrigin(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "full url returns scheme and host",
			in:   "https://cdn.example.com/logo.svg?x=1#frag",
			want: "https://cdn.example.com",
		},
		{
			name: "empty string returns empty",
			in:   "",
			want: "",
		},
		{
			name: "garbage returns empty",
			in:   "not a url at all ::: %%%",
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Origin(tc.in); got != tc.want {
				t.Errorf("Origin(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestLoad_RedirectOrigins pins the allowlist parsing contract: bare
// http(s) origins normalize; anything carrying a path, query, fragment,
// userinfo, or a non-http scheme refuses to boot.
func TestLoad_RedirectOrigins(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{name: "empty keeps internal-only behavior", raw: "", want: nil},
		{
			name: "list normalizes and keeps explicit ports",
			raw:  " http://127.0.0.1:8010 , https://app.example.com ",
			want: []string{"http://127.0.0.1:8010", "https://app.example.com"},
		},
		{name: "trailing slash is a bare origin", raw: "https://app.example.com/", want: []string{"https://app.example.com"}},
		{name: "path rejected", raw: "https://app.example.com/paper", wantErr: true},
		{
			name: "mixed-case host normalizes to lowercase",
			raw:  "https://APP.Example.COM",
			want: []string{"https://app.example.com"},
		},
		{name: "query rejected", raw: "https://app.example.com?x=1", wantErr: true},
		{name: "userinfo rejected", raw: "https://user@app.example.com", wantErr: true},
		{name: "non-http scheme rejected", raw: "javascript:alert(1)", wantErr: true},
		{name: "schemeless rejected", raw: "app.example.com", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SESAMO_DATABASE_URL", "postgres://sesamo:sesamo@localhost:5999/sesamo_dummy?sslmode=disable")
			t.Setenv("SESAMO_REDIRECT_ORIGINS", tc.raw)

			cfg, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Load() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if len(cfg.RedirectOrigins) != len(tc.want) {
				t.Fatalf("RedirectOrigins = %v, want %v", cfg.RedirectOrigins, tc.want)
			}
			for i := range tc.want {
				if cfg.RedirectOrigins[i] != tc.want[i] {
					t.Errorf("RedirectOrigins[%d] = %q, want %q", i, cfg.RedirectOrigins[i], tc.want[i])
				}
			}
		})
	}
}

// TestLoad_SignupPolicy pins the registration-policy values.
func TestLoad_SignupPolicy(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "default is public", raw: "", want: SignupPublic},
		{name: "disabled accepted", raw: "disabled", want: SignupDisabled},
		{name: "public accepted", raw: "public", want: SignupPublic},
		{name: "unknown value refuses to boot", raw: "invite-only", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SESAMO_DATABASE_URL", "postgres://sesamo:sesamo@localhost:5999/sesamo_dummy?sslmode=disable")
			t.Setenv("SESAMO_SIGNUP", tc.raw)

			cfg, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Load() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if cfg.Signup != tc.want {
				t.Errorf("Signup = %q, want %q", cfg.Signup, tc.want)
			}
		})
	}
}

// prodEnv is the smallest environment that satisfies every production
// invariant. Tests copy it and break exactly one thing, so a case that
// fails is unambiguous about which invariant fired. Every validated
// variable is listed (empty where "unset" is the point) to keep the
// tests hermetic against whatever the developer has exported.
func prodEnv() map[string]string {
	return map[string]string{
		"SESAMO_ENV":                               EnvProduction,
		"SESAMO_DATABASE_URL":                      "postgres://sesamo:sesamo@db.internal:5432/sesamo?sslmode=require",
		"SESAMO_BASE_URL":                          "https://auth.example.com",
		"SESAMO_COOKIE_SECURE":                     "true",
		"SESAMO_SERVICE_TOKEN":                     strings.Repeat("s", 32),
		"SESAMO_ADMIN_API_KEY":                     strings.Repeat("a", 32),
		"SESAMO_EMAIL_PROVIDER":                    "resend",
		"SESAMO_EMAIL_API_KEY":                     "re_live_deadbeef",
		"SESAMO_EMAIL_FROM":                        "auth@example.com",
		"SESAMO_EMAIL_OUTBOX_KEYS":                 "k1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"SESAMO_RESEND_WEBHOOK_SECRET":             "",
		"SESAMO_PROJECT_SLUG":                      "",
		"SESAMO_PROJECT_DISPLAY_NAME":              "",
		"SESAMO_SESSION_LIFETIME_DAYS":             "30",
		"SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES": "15",
		"SESAMO_SESSION_MAX_LIFETIME_DAYS":         "90",
		"SESAMO_SIGNUP":                            "",
		"SESAMO_REDIRECT_ORIGINS":                  "",
		"SESAMO_BRAND_LOGO_URL":                    "",
		"SESAMO_BRAND_PRIMARY_COLOR":               "",
		"SESAMO_BRAND_PAGE_BG":                     "",
		"SESAMO_BRAND_FONT_URL":                    "",
		"SESAMO_GOOGLE_CLIENT_ID":                  "",
		"SESAMO_GOOGLE_CLIENT_SECRET":              "",
		"SESAMO_GOOGLE_REDIRECT_URI":               "",
		"SESAMO_GITHUB_CLIENT_ID":                  "",
		"SESAMO_GITHUB_CLIENT_SECRET":              "",
		"SESAMO_GITHUB_REDIRECT_URI":               "",
		"SESAMO_APPLE_CLIENT_ID":                   "",
		"SESAMO_APPLE_TEAM_ID":                     "",
		"SESAMO_APPLE_KEY_ID":                      "",
		"SESAMO_APPLE_PRIVATE_KEY":                 "",
		"SESAMO_APPLE_REDIRECT_URI":                "",
		"PGSSLMODE":                                "",
	}
}

// applyEnv exports env for the duration of the test.
func applyEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
}

// TestLoad_ProductionInvariants pins the SESAMO_ENV=production contract:
// every dev-friendly default that is unsafe on a public deployment turns
// into a boot failure naming the variable to fix.
func TestLoad_ProductionInvariants(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		// want are substrings the error must contain; empty means the
		// config must load.
		want []string
	}{
		{name: "complete production config boots"},
		{
			name: "http base url rejected",
			env:  map[string]string{"SESAMO_BASE_URL": "http://localhost:7777"},
			want: []string{"SESAMO_BASE_URL"},
		},
		{
			name: "insecure cookie rejected",
			env:  map[string]string{"SESAMO_COOKIE_SECURE": "false"},
			want: []string{"SESAMO_COOKIE_SECURE"},
		},
		{
			name: "short service token rejected",
			env:  map[string]string{"SESAMO_SERVICE_TOKEN": "dev-service-token"},
			want: []string{"SESAMO_SERVICE_TOKEN", "32"},
		},
		{
			name: "missing admin key rejected",
			env:  map[string]string{"SESAMO_ADMIN_API_KEY": ""},
			want: []string{"SESAMO_ADMIN_API_KEY"},
		},
		{
			name: "identical service token and admin key rejected",
			env: map[string]string{
				"SESAMO_SERVICE_TOKEN": strings.Repeat("z", 32),
				"SESAMO_ADMIN_API_KEY": strings.Repeat("z", 32),
			},
			want: []string{"SESAMO_SERVICE_TOKEN", "SESAMO_ADMIN_API_KEY", "must differ"},
		},
		{
			name: "log email provider rejected",
			env:  map[string]string{"SESAMO_EMAIL_PROVIDER": "log"},
			want: []string{"SESAMO_EMAIL_PROVIDER"},
		},
		{
			name: "postmark accepted",
			env:  map[string]string{"SESAMO_EMAIL_PROVIDER": "postmark"},
		},
		{
			name: "missing email api key rejected",
			env:  map[string]string{"SESAMO_EMAIL_API_KEY": ""},
			want: []string{"SESAMO_EMAIL_API_KEY"},
		},
		{
			name: "missing email outbox keyring rejected",
			env:  map[string]string{"SESAMO_EMAIL_OUTBOX_KEYS": ""},
			want: []string{"SESAMO_EMAIL_OUTBOX_KEYS"},
		},
		{
			name: "localhost email sender rejected",
			env:  map[string]string{"SESAMO_EMAIL_FROM": "auth@localhost"},
			want: []string{"SESAMO_EMAIL_FROM"},
		},
		{
			name: "partial google block rejected",
			env: map[string]string{
				"SESAMO_GOOGLE_CLIENT_ID":    "google-id",
				"SESAMO_GOOGLE_REDIRECT_URI": "https://auth.example.com/auth/google/callback",
			},
			want: []string{"google", "SESAMO_GOOGLE_CLIENT_SECRET"},
		},
		{
			name: "complete google block accepted",
			env: map[string]string{
				"SESAMO_GOOGLE_CLIENT_ID":     "google-id",
				"SESAMO_GOOGLE_CLIENT_SECRET": "google-secret",
				"SESAMO_GOOGLE_REDIRECT_URI":  "https://auth.example.com/auth/google/callback",
			},
		},
		{
			name: "partial github block rejected",
			env:  map[string]string{"SESAMO_GITHUB_CLIENT_SECRET": "gh-secret"},
			want: []string{"github", "SESAMO_GITHUB_CLIENT_ID", "SESAMO_GITHUB_REDIRECT_URI"},
		},
		{
			name: "partial apple block rejected",
			env: map[string]string{
				"SESAMO_APPLE_CLIENT_ID":    "com.example.auth",
				"SESAMO_APPLE_TEAM_ID":      "TEAM123",
				"SESAMO_APPLE_PRIVATE_KEY":  "-----BEGIN PRIVATE KEY-----",
				"SESAMO_APPLE_REDIRECT_URI": "https://auth.example.com/auth/apple/callback",
			},
			want: []string{"apple", "SESAMO_APPLE_KEY_ID"},
		},
		{
			name: "sslmode disable rejected",
			env:  map[string]string{"SESAMO_DATABASE_URL": "postgres://u:p@db.internal:5432/sesamo?sslmode=disable"},
			want: []string{"SESAMO_DATABASE_URL", "sslmode=disable"},
		},
		{
			name: "sslmode prefer rejected",
			env:  map[string]string{"SESAMO_DATABASE_URL": "postgres://u:p@db.internal:5432/sesamo?sslmode=prefer"},
			want: []string{"SESAMO_DATABASE_URL", "sslmode=prefer"},
		},
		{
			name: "absent sslmode rejected",
			env:  map[string]string{"SESAMO_DATABASE_URL": "postgres://u:p@db.internal:5432/sesamo"},
			want: []string{"SESAMO_DATABASE_URL", "sslmode is required"},
		},
		{
			name: "verify-full accepted",
			env:  map[string]string{"SESAMO_DATABASE_URL": "postgres://u:p@db.internal:5432/sesamo?sslmode=verify-full"},
		},
		{
			name: "PGSSLMODE satisfies an absent dsn sslmode",
			env: map[string]string{
				"SESAMO_DATABASE_URL": "postgres://u:p@db.internal:5432/sesamo",
				"PGSSLMODE":           "verify-ca",
			},
		},
		{
			name: "keyword value dsn sslmode accepted",
			env:  map[string]string{"SESAMO_DATABASE_URL": "host=db.internal port=5432 dbname=sesamo sslmode=require"},
		},
		{
			name: "keyword value dsn without sslmode rejected",
			env:  map[string]string{"SESAMO_DATABASE_URL": "host=db.internal port=5432 dbname=sesamo"},
			want: []string{"sslmode is required"},
		},
		{
			name: "zero session lifetime rejected",
			env:  map[string]string{"SESAMO_SESSION_LIFETIME_DAYS": "0"},
			want: []string{"SESAMO_SESSION_LIFETIME_DAYS"},
		},
		{
			name: "unparseable session lifetime rejected",
			env:  map[string]string{"SESAMO_SESSION_LIFETIME_DAYS": "thirty"},
			want: []string{"SESAMO_SESSION_LIFETIME_DAYS", "not an integer"},
		},
		{
			name: "zero renewal threshold rejected",
			env:  map[string]string{"SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES": "-1"},
			want: []string{"SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES"},
		},
		{
			name: "unparseable renewal threshold rejected",
			env:  map[string]string{"SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES": "15m"},
			want: []string{"SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES", "not an integer"},
		},
		{
			name: "zero max lifetime rejected",
			env:  map[string]string{"SESAMO_SESSION_MAX_LIFETIME_DAYS": "0"},
			want: []string{"SESAMO_SESSION_MAX_LIFETIME_DAYS"},
		},
		{
			name: "every violation is reported at once",
			env: map[string]string{
				"SESAMO_BASE_URL":       "http://auth.example.com",
				"SESAMO_COOKIE_SECURE":  "false",
				"SESAMO_EMAIL_PROVIDER": "log",
			},
			want: []string{"SESAMO_BASE_URL", "SESAMO_COOKIE_SECURE", "SESAMO_EMAIL_PROVIDER"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := prodEnv()
			for k, v := range tc.env {
				env[k] = v
			}
			applyEnv(t, env)

			cfg, err := Load()
			if len(tc.want) > 0 {
				if err == nil {
					t.Fatalf("Load() error = nil, want an error mentioning %v", tc.want)
				}
				for _, want := range tc.want {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("Load() error = %q, want it to mention %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if cfg.Env != EnvProduction {
				t.Errorf("Env = %q, want %q", cfg.Env, EnvProduction)
			}
		})
	}
}

// TestLoad_SessionMaxLifetime pins the absolute session cap: the default,
// the dev-only tolerance for a nonsense value, and the cross-variable
// invariant that holds in every environment.
func TestLoad_SessionMaxLifetime(t *testing.T) {
	const devDSN = "postgres://sesamo:sesamo@localhost:5999/sesamo_dummy?sslmode=disable"

	cases := []struct {
		name        string
		env         map[string]string
		want        time.Duration
		wantErrPart string
	}{
		{
			name: "unset defaults to 90 days",
			want: 90 * 24 * time.Hour,
		},
		{
			name: "explicit value is honored",
			env:  map[string]string{"SESAMO_SESSION_MAX_LIFETIME_DAYS": "180"},
			want: 180 * 24 * time.Hour,
		},
		{
			name: "development falls back to the default on a nonsense value",
			env:  map[string]string{"SESAMO_SESSION_MAX_LIFETIME_DAYS": "0"},
			want: 90 * 24 * time.Hour,
		},
		{
			name: "development falls back to the default on an unparseable value",
			env:  map[string]string{"SESAMO_SESSION_MAX_LIFETIME_DAYS": "ninety"},
			want: 90 * 24 * time.Hour,
		},
		{
			name: "cap shorter than one session lifetime refuses to boot",
			env: map[string]string{
				"SESAMO_SESSION_MAX_LIFETIME_DAYS": "10",
				"SESAMO_SESSION_LIFETIME_DAYS":     "30",
			},
			wantErrPart: "SESAMO_SESSION_MAX_LIFETIME_DAYS",
		},
		{
			name: "cap equal to the session lifetime is allowed",
			env: map[string]string{
				"SESAMO_SESSION_MAX_LIFETIME_DAYS": "30",
				"SESAMO_SESSION_LIFETIME_DAYS":     "30",
			},
			want: 30 * 24 * time.Hour,
		},
		{
			name: "default cap rejects a longer session lifetime",
			env:  map[string]string{"SESAMO_SESSION_LIFETIME_DAYS": "365"},
			// The invariant holds in development too: a session that
			// outlives its own ceiling is nonsense, not a dev shortcut.
			wantErrPart: "SESAMO_SESSION_LIFETIME_DAYS",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{
				"SESAMO_ENV":                       "",
				"SESAMO_DATABASE_URL":              devDSN,
				"SESAMO_SESSION_MAX_LIFETIME_DAYS": "",
				"SESAMO_SESSION_LIFETIME_DAYS":     "",
			}
			for k, v := range tc.env {
				env[k] = v
			}
			applyEnv(t, env)

			cfg, err := Load()
			if tc.wantErrPart != "" {
				if err == nil {
					t.Fatalf("Load() error = nil, want an error mentioning %q", tc.wantErrPart)
				}
				if !strings.Contains(err.Error(), tc.wantErrPart) {
					t.Errorf("Load() error = %q, want it to mention %q", err, tc.wantErrPart)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if cfg.SessionMaxLifetime != tc.want {
				t.Errorf("SessionMaxLifetime = %s, want %s", cfg.SessionMaxLifetime, tc.want)
			}
		})
	}
}

// TestLoad_DevelopmentDefaults pins that adding SESAMO_ENV changed
// nothing for an operator who never sets it: the permissive local
// defaults still boot, unparseable integers are still silently ignored,
// and only an unknown environment name is fatal.
func TestLoad_DevelopmentDefaults(t *testing.T) {
	applyEnv(t, map[string]string{
		"SESAMO_ENV":                               "",
		"SESAMO_DATABASE_URL":                      "postgres://sesamo:sesamo@localhost:5999/sesamo_dummy?sslmode=disable",
		"SESAMO_BASE_URL":                          "",
		"SESAMO_COOKIE_SECURE":                     "",
		"SESAMO_SERVICE_TOKEN":                     "dev-service-token",
		"SESAMO_ADMIN_API_KEY":                     "dev-admin-key",
		"SESAMO_EMAIL_PROVIDER":                    "",
		"SESAMO_EMAIL_API_KEY":                     "",
		"SESAMO_EMAIL_FROM":                        "",
		"SESAMO_SESSION_LIFETIME_DAYS":             "not-a-number",
		"SESAMO_ROLLING_RENEWAL_THRESHOLD_MINUTES": "",
		"SESAMO_SESSION_MAX_LIFETIME_DAYS":         "",
		"SESAMO_GOOGLE_CLIENT_ID":                  "google-id-only",
		"SESAMO_GOOGLE_CLIENT_SECRET":              "",
		"SESAMO_GOOGLE_REDIRECT_URI":               "",
	})

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.Env != EnvDevelopment {
		t.Errorf("Env = %q, want %q", cfg.Env, EnvDevelopment)
	}
	if cfg.BaseURL != "http://localhost:7777" {
		t.Errorf("BaseURL = %q, want the http localhost default", cfg.BaseURL)
	}
	if cfg.CookieSecure {
		t.Error("CookieSecure = true, want false by default")
	}
	if cfg.EmailProvider != "log" {
		t.Errorf("EmailProvider = %q, want %q", cfg.EmailProvider, "log")
	}
	if cfg.SessionLifetime != 30*24*time.Hour {
		t.Errorf("SessionLifetime = %s, want the 30-day default despite the unparseable value", cfg.SessionLifetime)
	}
	if cfg.RollingRenewalThreshold != 15*time.Minute {
		t.Errorf("RollingRenewalThreshold = %s, want 15m", cfg.RollingRenewalThreshold)
	}
	if cfg.SessionMaxLifetime != 90*24*time.Hour {
		t.Errorf("SessionMaxLifetime = %s, want 90 days", cfg.SessionMaxLifetime)
	}
	if cfg.Google.Enabled() {
		t.Error("Google.Enabled() = true, want false for a half-configured block in development")
	}
}

// TestLoad_UnknownEnvRefusesToBoot: a typo in SESAMO_ENV must not
// silently select the permissive profile.
func TestLoad_UnknownEnvRefusesToBoot(t *testing.T) {
	applyEnv(t, map[string]string{
		"SESAMO_ENV":          "staging",
		"SESAMO_DATABASE_URL": "postgres://sesamo:sesamo@localhost:5999/sesamo_dummy?sslmode=disable",
	})
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SESAMO_ENV") {
		t.Fatalf("Load() error = %v, want an error mentioning SESAMO_ENV", err)
	}
}

// TestLoad_ProjectSlug pins deployment identity: the default slug is
// valid, custom slugs are validated in every environment (the value
// lands verbatim in the public descriptor), and a broken slug is a boot
// failure, not a silently mangled identity.
func TestLoad_ProjectSlug(t *testing.T) {
	base := map[string]string{
		"SESAMO_DATABASE_URL": "postgres://sesamo:sesamo@localhost:5999/sesamo_dummy?sslmode=disable",
	}
	t.Run("default", func(t *testing.T) {
		applyEnv(t, base)
		t.Setenv("SESAMO_PROJECT_SLUG", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() unexpected error: %v", err)
		}
		if cfg.ProjectSlug != "sesamo" {
			t.Errorf("ProjectSlug = %q, want %q", cfg.ProjectSlug, "sesamo")
		}
	})
	t.Run("custom slug accepted", func(t *testing.T) {
		applyEnv(t, base)
		t.Setenv("SESAMO_PROJECT_SLUG", "marketmaker-prod")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() unexpected error: %v", err)
		}
		if cfg.ProjectSlug != "marketmaker-prod" {
			t.Errorf("ProjectSlug = %q, want %q", cfg.ProjectSlug, "marketmaker-prod")
		}
	})
	for _, bad := range []string{"Marketmaker", "-prod", "prod-", "a b", "año"} {
		t.Run("invalid slug "+bad, func(t *testing.T) {
			applyEnv(t, base)
			t.Setenv("SESAMO_PROJECT_SLUG", bad)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SESAMO_PROJECT_SLUG") {
				t.Fatalf("Load() error = %v, want an error mentioning SESAMO_PROJECT_SLUG", err)
			}
		})
	}
}
