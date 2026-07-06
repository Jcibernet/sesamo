package config

import "testing"

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
