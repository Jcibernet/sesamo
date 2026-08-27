// Package ui serves Sésamo's embedded HTML screens. All assets are
// compiled into the binary via embed.FS so there is nothing to deploy
// alongside it. Theming is done entirely through CSS custom properties
// (design tokens) that an operator can override with a single external
// stylesheet (SESAMO_THEME_CSS_URL) — no template forking required.
package ui

import (
	"embed"
	"html/template"
	"io"
	"strings"
)

//go:embed templates/*.html assets/*.css
var files embed.FS

// templates are parsed once at startup.
var templates = template.Must(template.ParseFS(files, "templates/*.html"))

// LoginData drives the login screen.
type LoginData struct {
	BaseURL     string
	Providers   []string // enabled OAuth provider names
	Password    bool     // password login enabled
	MagicLink   bool     // magic-link login enabled
	ThemeCSSURL string   // optional operator override stylesheet
	BrandCSS    bool     // link the generated /ui/brand.css
	LogoURL     string   // optional brand logo rendered atop the card
	Error       string   // optional error code to surface
	// CSRFToken is the request half of the double-submit pair; the other
	// half is the sesamo_csrf cookie set alongside this render.
	CSRFToken string
}

// MessageData drives the generic outcome screen (e.g. "check your email").
type MessageData struct {
	BaseURL     string
	Title       string
	Body        string
	ThemeCSSURL string
	BrandCSS    bool
	LogoURL     string
}

// RenderLogin writes the login page.
func RenderLogin(w io.Writer, d LoginData) error {
	return templates.ExecuteTemplate(w, "login.html", d)
}

// RenderMessage writes a generic message page.
func RenderMessage(w io.Writer, d MessageData) error {
	return templates.ExecuteTemplate(w, "message.html", d)
}

// ResetRequestData drives the "request a reset link" form page.
type ResetRequestData struct {
	BaseURL     string
	ThemeCSSURL string
	BrandCSS    bool
	LogoURL     string
	CSRFToken   string
}

// ResetConfirmData drives the "choose a new password" form page. Token
// arrives via the emailed link's query string and is only consumed when
// the form POSTs — rendering this page must never spend it.
type ResetConfirmData struct {
	BaseURL     string
	ThemeCSSURL string
	BrandCSS    bool
	LogoURL     string
	Token       string
	CSRFToken   string
}

// RenderResetRequest writes the reset-request form page.
func RenderResetRequest(w io.Writer, d ResetRequestData) error {
	return templates.ExecuteTemplate(w, "reset_request.html", d)
}

// RenderResetConfirm writes the new-password form page.
func RenderResetConfirm(w io.Writer, d ResetConfirmData) error {
	return templates.ExecuteTemplate(w, "reset_confirm.html", d)
}

// BaseCSS returns the embedded default stylesheet (design tokens +
// layout). Served at a stable path so the theme override can @import or
// layer on top of it.
func BaseCSS() ([]byte, error) {
	return files.ReadFile("assets/theme.css")
}

// BrandInput is the no-code branding layer: values arrive from
// SESAMO_BRAND_* env vars, already validated by config (safe-character
// CSS values, absolute http(s) URLs).
type BrandInput struct {
	LogoURL      string
	PrimaryColor string
	PageBG       string
	FontURL      string
}

// BrandCSS generates the /ui/brand.css stylesheet from the branding
// input: a tiny token-override layer between theme.css and the
// operator's SESAMO_THEME_CSS_URL. Returns nil when nothing is set.
// Served from 'self', so the strict CSP needs no style-src change.
func BrandCSS(b BrandInput) []byte {
	if b.PrimaryColor == "" && b.PageBG == "" && b.FontURL == "" {
		return nil
	}
	var sb strings.Builder
	sb.WriteString("/* generated from SESAMO_BRAND_* — layers over theme.css */\n")
	if b.FontURL != "" {
		format := "woff"
		if strings.HasSuffix(strings.ToLower(b.FontURL), ".woff2") {
			format = "woff2"
		}
		sb.WriteString("@font-face {\n  font-family: \"SesamoBrand\";\n  src: url(\"")
		sb.WriteString(b.FontURL)
		sb.WriteString("\") format(\"")
		sb.WriteString(format)
		sb.WriteString("\");\n  font-display: swap;\n}\n")
	}
	sb.WriteString(":root {\n")
	if b.PrimaryColor != "" {
		sb.WriteString("  --sesamo-primary: " + b.PrimaryColor + ";\n")
	}
	if b.PageBG != "" {
		// Solid colors go to background-color; gradients are images.
		if strings.Contains(b.PageBG, "gradient") {
			sb.WriteString("  --sesamo-page-bg-image: " + b.PageBG + ";\n")
		} else {
			sb.WriteString("  --sesamo-bg: " + b.PageBG + ";\n")
		}
	}
	if b.FontURL != "" {
		sb.WriteString("  --sesamo-font: \"SesamoBrand\", system-ui, sans-serif;\n")
	}
	sb.WriteString("}\n")
	return []byte(sb.String())
}
