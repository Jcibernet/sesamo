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
	Error       string   // optional error code to surface
}

// MessageData drives the generic outcome screen (e.g. "check your email").
type MessageData struct {
	BaseURL     string
	Title       string
	Body        string
	ThemeCSSURL string
}

// RenderLogin writes the login page.
func RenderLogin(w io.Writer, d LoginData) error {
	return templates.ExecuteTemplate(w, "login.html", d)
}

// RenderMessage writes a generic message page.
func RenderMessage(w io.Writer, d MessageData) error {
	return templates.ExecuteTemplate(w, "message.html", d)
}

// BaseCSS returns the embedded default stylesheet (design tokens +
// layout). Served at a stable path so the theme override can @import or
// layer on top of it.
func BaseCSS() ([]byte, error) {
	return files.ReadFile("assets/theme.css")
}
