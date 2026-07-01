package http

import (
	"net/http"
	"time"

	"github.com/jcibernet/sesamo/internal/crypto"
	"github.com/jcibernet/sesamo/internal/email"
	"github.com/jcibernet/sesamo/internal/oauth"
	"github.com/jcibernet/sesamo/internal/session"
	"github.com/jcibernet/sesamo/internal/ui"
)

func (s *Server) registerEndUser() {
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("GET /ui/theme.css", s.handleThemeCSS)
	s.mux.HandleFunc("POST /login", s.handlePasswordLogin)
	s.mux.HandleFunc("POST /signup", s.handleSignup)
	s.mux.HandleFunc("POST /logout", s.handleLogout) // POST-only (anti-CSRF)
	s.mux.HandleFunc("GET /auth/{provider}", s.handleOAuthStart)
	s.mux.HandleFunc("GET /auth/{provider}/callback", s.handleOAuthCallback)
	s.mux.HandleFunc("POST /reset", s.handleResetRequest)
	s.mux.HandleFunc("POST /reset/confirm", s.handleResetConfirm)
	s.mux.HandleFunc("GET /verify", s.handleVerify)
	s.mux.HandleFunc("POST /magiclink", s.handleMagicLinkRequest)
	s.mux.HandleFunc("GET /magiclink/confirm", s.handleMagicLinkConfirm)
}

// handleLoginPage renders the embedded login screen, or returns the
// available methods as JSON in headless mode (Accept: application/json or
// ?mode=json) so a custom frontend can render its own UI.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{
			"providers": s.providers.Names(),
			"methods":   []string{"password", "magiclink"},
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui.RenderLogin(w, ui.LoginData{
		BaseURL:     s.cfg.BaseURL,
		Providers:   s.providers.Names(),
		Password:    true,
		MagicLink:   true,
		ThemeCSSURL: s.cfg.ThemeCSSURL,
		Error:       r.URL.Query().Get("error"),
	}); err != nil {
		s.log.Error("render login", "err", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
	}
}

// handleThemeCSS serves the embedded base stylesheet (design tokens).
func (s *Server) handleThemeCSS(w http.ResponseWriter, r *http.Request) {
	css, err := ui.BaseCSS()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(css)
}

// handleOAuthStart redirects to the provider with state + PKCE.
func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	prov, ok := s.providers.Get(name)
	if !ok {
		writeError(w, http.StatusNotFound, codeNotFound, "Proveedor no disponible.")
		return
	}

	state := crypto.GenerateOAuthState()
	pkce := oauth.NewPKCE()
	s.setTransient(w, cookieOAuthState, state)
	s.setTransient(w, cookiePKCE, pkce.Verifier)

	if rt := r.URL.Query().Get("redirect_to"); rt != "" {
		s.setTransient(w, cookiePostLogin, safeInternalPath(rt))
	}

	url := prov.AuthorizeURL(state, pkce.Verifier)
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{"authorize_url": url})
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

// handleOAuthCallback validates state, exchanges the code, upserts the
// user, and starts a session.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	prov, ok := s.providers.Get(name)
	if !ok {
		writeError(w, http.StatusNotFound, codeNotFound, "Proveedor no disponible.")
		return
	}

	code := r.URL.Query().Get("code")
	stateQ := r.URL.Query().Get("state")
	stateC := cookieValue(r, cookieOAuthState)
	verifier := cookieValue(r, cookiePKCE)

	// Clear transients regardless of outcome.
	s.clearTransient(w, cookieOAuthState)
	s.clearTransient(w, cookiePKCE)

	if code == "" || stateQ == "" {
		s.oauthFail(w, r, codeInvalidRequest, "Falta el código o el estado.")
		return
	}
	// CSRF: state from cookie must match state from provider.
	if stateC == "" || !crypto.SafeEqual([]byte(stateC), []byte(stateQ)) {
		s.oauthFail(w, r, codeStateMismatch, "Estado inválido. Probá de nuevo.")
		return
	}

	profile, err := prov.Exchange(r.Context(), code, verifier)
	if err != nil {
		s.log.Warn("oauth exchange failed", "provider", name, "err", err)
		s.oauthFail(w, r, codeOAuthFailed, "No pudimos iniciar sesión. Probá de nuevo.")
		return
	}

	res, err := s.users.UpsertByOAuth(r.Context(), profile)
	if err != nil {
		s.log.Error("upsert oauth user", "err", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}

	s.startSessionAndRedirect(w, r, res.UserID)
}

// handlePasswordLogin authenticates email+password. Anti-enumeration:
// identical error + dummy hash work when the user is absent.
func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	emailAddr, password := r.FormValue("email"), r.FormValue("password")
	if emailAddr == "" || password == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Email y contraseña requeridos.")
		return
	}

	// Per-identity + per-IP rate limiting (Step 7 enforcement).
	if !s.checkLoginRate(w, r, emailAddr) {
		return
	}

	userID, hash, ok, err := s.users.PasswordHash(r.Context(), emailAddr)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	if !ok {
		// User missing or has no password: do dummy work to equalize
		// timing, then return the SAME generic error.
		crypto.DummyVerify(password)
		writeError(w, http.StatusUnauthorized, codeInvalidCredentials, "Email o contraseña incorrectos.")
		return
	}

	valid, needsRehash, err := crypto.VerifyPassword(password, hash)
	if err != nil || !valid {
		writeError(w, http.StatusUnauthorized, codeInvalidCredentials, "Email o contraseña incorrectos.")
		return
	}

	// Lazy migration: re-hash bcrypt (Auth0 import) to Argon2id.
	if needsRehash {
		if newHash, err := crypto.HashPassword(password); err == nil {
			_ = s.users.SetPassword(r.Context(), userID, newHash)
		}
	}

	s.startSessionAndRedirect(w, r, userID)
}

// handleSignup creates a password user and sends a verification email.
func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	emailAddr, password := r.FormValue("email"), r.FormValue("password")
	if emailAddr == "" || len(password) < 8 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Email válido y contraseña de 8+ caracteres requeridos.")
		return
	}

	hash, err := crypto.HashPassword(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	id := crypto.UUIDv7()
	if err := s.users.CreateWithPassword(r.Context(), id, emailAddr, hash); err != nil {
		// Do not reveal whether the email already exists: respond 200 as
		// if a verification email was sent (anti-enumeration).
		s.log.Info("signup conflict or error (masked)", "err", err)
		writeJSON(w, http.StatusOK, map[string]string{"status": "verification_sent"})
		return
	}

	s.sendOneTimeLink(r, id, emailAddr, email.PurposeVerify, "/verify",
		"Verificá tu email", 24*time.Hour)
	writeJSON(w, http.StatusOK, map[string]string{"status": "verification_sent"})
}

// handleLogout invalidates the session and clears the cookie. POST-only.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token := cookieValue(r, s.cfg.CookieName); token != "" {
		_ = s.sessions.Revoke(r.Context(), token)
	}
	s.clearSessionCookie(w)
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleResetRequest always returns 200 to avoid revealing whether the
// email exists. If it does, a reset link is sent.
func (s *Server) handleResetRequest(w http.ResponseWriter, r *http.Request) {
	emailAddr := r.FormValue("email")
	if emailAddr == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Email requerido.")
		return
	}
	if !s.checkLoginRate(w, r, emailAddr) {
		return
	}
	u, err := s.users.ByEmail(r.Context(), emailAddr)
	if err == nil && u != nil {
		s.sendOneTimeLink(r, u.ID, emailAddr, email.PurposeReset, "/reset/confirm",
			"Restablecé tu contraseña", 15*time.Minute)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset_sent"})
}

// handleResetConfirm consumes a reset token and sets the new password.
func (s *Server) handleResetConfirm(w http.ResponseWriter, r *http.Request) {
	token, password := r.FormValue("token"), r.FormValue("password")
	if token == "" || len(password) < 8 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Token y contraseña de 8+ caracteres requeridos.")
		return
	}
	userID, err := s.tokens.Consume(r.Context(), token, email.PurposeReset)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Token inválido o expirado.")
		return
	}
	hash, err := crypto.HashPassword(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	if err := s.users.SetPassword(r.Context(), userID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	// Reset implies privilege change: kill all existing sessions.
	_ = s.sessions.RevokeAllForUser(r.Context(), userID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "password_reset"})
}

// handleVerify consumes an email verification token.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Token requerido.")
		return
	}
	userID, err := s.tokens.Consume(r.Context(), token, email.PurposeVerify)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Token inválido o expirado.")
		return
	}
	if err := s.users.MarkEmailVerified(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "email_verified"})
}

// handleMagicLinkRequest emails a one-time login link. Always 200.
func (s *Server) handleMagicLinkRequest(w http.ResponseWriter, r *http.Request) {
	emailAddr := r.FormValue("email")
	if emailAddr == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Email requerido.")
		return
	}
	if !s.checkLoginRate(w, r, emailAddr) {
		return
	}
	u, err := s.users.ByEmail(r.Context(), emailAddr)
	if err == nil && u != nil {
		s.sendOneTimeLink(r, u.ID, emailAddr, email.PurposeMagicLink, "/magiclink/confirm",
			"Tu enlace de acceso", 15*time.Minute)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "magiclink_sent"})
}

// handleMagicLinkConfirm consumes a magic link and starts a session.
func (s *Server) handleMagicLinkConfirm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Token requerido.")
		return
	}
	userID, err := s.tokens.Consume(r.Context(), token, email.PurposeMagicLink)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Enlace inválido o expirado.")
		return
	}
	// A magic link also verifies the email (proof of inbox control).
	_ = s.users.MarkEmailVerified(r.Context(), userID)
	s.startSessionAndRedirect(w, r, userID)
}

// startSessionAndRedirect creates a session, sets the cookie, and either
// returns JSON (headless) or redirects to the post-login target.
func (s *Server) startSessionAndRedirect(w http.ResponseWriter, r *http.Request, userID string) {
	ua := r.UserAgent()
	ip := clientIP(r)
	created, err := s.sessions.Create(r.Context(), session.CreateInput{
		UserID: userID, UserAgent: &ua, IPFirst: &ip,
	})
	if err != nil {
		s.log.Error("create session", "err", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	s.setSessionCookie(w, created.Token, created.ExpiresAt)

	target := safeInternalPath(cookieValue(r, cookiePostLogin))
	s.clearTransient(w, cookiePostLogin)

	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "authenticated", "redirect_to": target,
		})
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// sendOneTimeLink issues a token and emails a link to path?token=...
func (s *Server) sendOneTimeLink(r *http.Request, userID, to string, purpose email.Purpose, path, subject string, ttl time.Duration) {
	token, err := s.tokens.Issue(r.Context(), userID, purpose, ttl)
	if err != nil {
		s.log.Error("issue token", "err", err, "purpose", purpose)
		return
	}
	link := s.cfg.BaseURL + path + "?token=" + token
	body := subject + ":\n\n" + link + "\n\nEste enlace expira pronto y se usa una sola vez."
	if err := s.mailer.Send(r.Context(), email.Message{To: to, Subject: subject, Body: body}); err != nil {
		s.log.Error("send email", "err", err)
	}
}

// oauthFail renders an OAuth failure as JSON or a redirect to /login.
func (s *Server) oauthFail(w http.ResponseWriter, r *http.Request, code, msg string) {
	s.clearSessionCookie(w)
	if wantsJSON(r) {
		writeError(w, http.StatusBadRequest, code, msg)
		return
	}
	http.Redirect(w, r, "/login?error="+code, http.StatusFound)
}
