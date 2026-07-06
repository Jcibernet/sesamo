package http

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jcibernet/sesamo/internal/config"
)

// Fixture values for the branded harness — chosen to exercise every
// BrandCSS/CSP code path (a gradient PageBG and a .woff2 FontURL) in one
// pass.
const (
	brandLogoURL = "https://cdn.example.com/logo.svg"
	brandPrimary = "#e11d48"
	brandPageBG  = "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"
	brandFontURL = "https://fonts.example.com/brand.woff2"
)

// newBrandedHarness is a local variant of newHarness with SESAMO_BRAND_*
// equivalents populated directly on the config (Auth0-parity branding
// layer), used to verify /ui/brand.css, the login page/JSON payload, and
// the CSP without touching newHarness used by every other test.
func newBrandedHarness(t *testing.T) *harness {
	return newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.Brand = config.BrandConfig{
			LogoURL:      brandLogoURL,
			PrimaryColor: brandPrimary,
			PageBG:       brandPageBG,
			FontURL:      brandFontURL,
		}
	})
}

// getJSON issues a GET with Accept: application/json and returns the raw
// body alongside the response.
func getJSON(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, body
}

// loginJSON mirrors the shape returned by GET /login with
// Accept: application/json. Branding is a pointer so a decode with no
// "branding" key in the response leaves it nil — that is how the
// unbranded-harness test asserts the key is absent rather than merely
// empty.
type loginJSON struct {
	Providers []string `json:"providers"`
	Methods   []string `json:"methods"`
	Branding  *struct {
		LogoURL        string `json:"logo_url"`
		PrimaryColor   string `json:"primary_color"`
		PageBackground string `json:"page_background"`
		FontURL        string `json:"font_url"`
		ThemeCSSURL    string `json:"theme_css_url"`
	} `json:"branding"`
}

// ── Branding: /ui/brand.css is served with the generated stylesheet ───
func TestBranding01_BrandCSSServed(t *testing.T) {
	h := newBrandedHarness(t)
	res, err := http.Get(h.srv.URL + "/ui/brand.css")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/css") {
		t.Errorf("Content-Type = %q, want text/css", ct)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), brandPrimary) {
		t.Errorf("brand.css body missing %q:\n%s", brandPrimary, body)
	}
}

// ── Branding: the HTML login page links brand.css and renders the logo ─
func TestBranding02_LoginHTMLIncludesBrandAssets(t *testing.T) {
	h := newBrandedHarness(t)
	res, err := http.Get(h.srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	if !strings.Contains(html, "/ui/brand.css") {
		t.Errorf("login HTML missing /ui/brand.css link:\n%s", html)
	}
	if !strings.Contains(html, `class="sesamo-logo"`) {
		t.Errorf("login HTML missing sesamo-logo img:\n%s", html)
	}
	if !strings.Contains(html, brandLogoURL) {
		t.Errorf("login HTML missing logo URL %q:\n%s", brandLogoURL, html)
	}
}

// ── Branding: the headless JSON login payload exposes the branding
// object (Auth0 branding-API parity for custom frontends) ─────────────
func TestBranding03_LoginJSONIncludesBranding(t *testing.T) {
	h := newBrandedHarness(t)
	res, body := getJSON(t, h.srv.URL+"/login")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", res.StatusCode, body)
	}
	var payload loginJSON
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if payload.Branding == nil {
		t.Fatalf("branding key missing from JSON payload: %s", body)
	}
	if payload.Branding.LogoURL != brandLogoURL {
		t.Errorf("branding.logo_url = %q, want %q", payload.Branding.LogoURL, brandLogoURL)
	}
	if payload.Branding.PrimaryColor != brandPrimary {
		t.Errorf("branding.primary_color = %q, want %q", payload.Branding.PrimaryColor, brandPrimary)
	}
}

// ── Branding: CSP is widened to exactly the brand logo/font origins ───
func TestBranding04_CSPIncludesBrandOrigins(t *testing.T) {
	h := newBrandedHarness(t)
	res, err := http.Get(h.srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	csp := res.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("missing Content-Security-Policy header")
	}
	if !strings.Contains(csp, "img-src 'self' data: https://cdn.example.com") {
		t.Errorf("CSP missing branded img-src, got: %s", csp)
	}
	if !strings.Contains(csp, "font-src 'self' https://fonts.example.com") {
		t.Errorf("CSP missing branded font-src, got: %s", csp)
	}
}

// ── Branding: an unbranded deployment serves no brand.css and emits no
// branding key at all — absence, not empty values ─────────────────────
func TestBranding05_UnbrandedHarnessHasNoBranding(t *testing.T) {
	h := newHarness(t)

	res, err := http.Get(h.srv.URL + "/ui/brand.css")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("/ui/brand.css status = %d, want 404", res.StatusCode)
	}

	jres, body := getJSON(t, h.srv.URL+"/login")
	if jres.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", jres.StatusCode, body)
	}
	if strings.Contains(string(body), `"branding"`) {
		t.Errorf("unbranded /login JSON should have no branding key: %s", body)
	}
	var payload loginJSON
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode: %v; body=%s", err, body)
	}
	if payload.Branding != nil {
		t.Errorf("unbranded /login JSON decoded a non-nil branding object: %+v", payload.Branding)
	}
}
