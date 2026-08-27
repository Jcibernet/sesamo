package http

import (
	"strings"
	"testing"

	"github.com/jcibernet/sesamo/internal/config"
)

// appleTestPEM is a syntactically valid but semantically wrong PEM: the
// block parses as PEM and fails as a PKCS#8 EC key, which is what an
// operator who pasted the wrong file actually produces.
const appleTestPEM = `-----BEGIN PRIVATE KEY-----
bm90IGEga2V5
-----END PRIVATE KEY-----`

// TestBuildProviders pins the boot contract for OAuth wiring: a provider
// the operator configured either ends up registered or stops the boot.
// Silently disabling Apple after a PEM error (the previous behavior) left
// a server whose Apple button 404s and one warning line in the log.
func TestBuildProviders(t *testing.T) {
	cases := []struct {
		name        string
		cfg         config.Config
		wantNames   []string
		wantErrPart string
	}{
		{
			name:      "no providers configured registers none",
			cfg:       config.Config{},
			wantNames: nil,
		},
		{
			name: "google and github register",
			cfg: config.Config{
				Google: config.OAuthProviderConfig{
					ClientID:     "google-id",
					ClientSecret: "google-secret",
					RedirectURI:  "https://auth.example.com/auth/google/callback",
				},
				GitHub: config.OAuthProviderConfig{
					ClientID:     "github-id",
					ClientSecret: "github-secret",
					RedirectURI:  "https://auth.example.com/auth/github/callback",
				},
			},
			wantNames: []string{"github", "google"},
		},
		{
			name: "apple with an unparseable private key fails boot",
			cfg: config.Config{
				Apple: config.AppleConfig{
					ClientID:    "com.example.auth",
					TeamID:      "TEAM123456",
					KeyID:       "KEY123456",
					PrivateKey:  "not a pem at all",
					RedirectURI: "https://auth.example.com/auth/apple/callback",
				},
			},
			wantErrPart: "apple",
		},
		{
			name: "apple with a valid pem block holding a non-key fails boot",
			cfg: config.Config{
				Apple: config.AppleConfig{
					ClientID:    "com.example.auth",
					TeamID:      "TEAM123456",
					KeyID:       "KEY123456",
					PrivateKey:  appleTestPEM,
					RedirectURI: "https://auth.example.com/auth/apple/callback",
				},
			},
			wantErrPart: "apple",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			reg, err := buildProviders(&cfg)
			if tc.wantErrPart != "" {
				if err == nil {
					t.Fatalf("buildProviders() error = nil, want an error mentioning %q", tc.wantErrPart)
				}
				if !strings.Contains(err.Error(), tc.wantErrPart) {
					t.Errorf("buildProviders() error = %q, want it to mention %q", err, tc.wantErrPart)
				}
				if reg != nil {
					t.Error("buildProviders() registry != nil on error, want nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildProviders() unexpected error: %v", err)
			}
			got := reg.Names()
			if len(got) != len(tc.wantNames) {
				t.Fatalf("registered providers = %v, want %v", got, tc.wantNames)
			}
			for _, name := range tc.wantNames {
				if _, ok := reg.Get(name); !ok {
					t.Errorf("provider %q not registered (got %v)", name, got)
				}
			}
		})
	}
}
