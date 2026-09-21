package http

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jcibernet/sesamo/internal/audit"
	"github.com/jcibernet/sesamo/internal/config"
	"github.com/jcibernet/sesamo/internal/crypto"
	"github.com/jcibernet/sesamo/internal/email"
	"github.com/jcibernet/sesamo/internal/oauth"
	"github.com/jcibernet/sesamo/internal/session"
	"github.com/jcibernet/sesamo/internal/ui"
	"github.com/jcibernet/sesamo/internal/user"
)

func (s *Server) registerEndUser() {
	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("GET /ui/theme.css", s.handleThemeCSS)
	s.mux.HandleFunc("GET /ui/brand.css", s.handleBrandCSS)
	s.mux.HandleFunc("POST /login", s.handlePasswordLogin)
	s.mux.HandleFunc("POST /signup", s.handleSignup)
	s.mux.HandleFunc("POST /logout", s.handleLogout) // POST-only + CSRF token
	s.mux.HandleFunc("GET /auth/{provider}", s.handleOAuthStart)
	s.mux.HandleFunc("GET /auth/{provider}/callback", s.handleOAuthCallback)
	s.mux.HandleFunc("GET /reset", s.handleResetRequestPage)
	s.mux.HandleFunc("POST /reset", s.handleResetRequest)
	s.mux.HandleFunc("GET /reset/confirm", s.handleResetConfirmPage)
	s.mux.HandleFunc("POST /reset/confirm", s.handleResetConfirm)
	s.mux.HandleFunc("GET /verify", s.handleVerify)
	s.mux.HandleFunc("POST /magiclink", s.handleMagicLinkRequest)
	s.mux.HandleFunc("GET /magiclink/confirm", s.handleMagicLinkConfirm)
}

// handleLoginPage renders the embedded login screen, or returns the
// available methods as JSON in headless mode (Accept: application/json or
// ?mode=json) so a custom frontend can render its own UI.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// Remember where the consuming app wants the user back. Password and
	// magic-link flows have no provider round trip to carry state, so the
	// login page is where the destination enters the system.
	s.captureRedirect(w, r)
	// The CSRF cookie is HttpOnly, so a headless frontend cannot read it
	// back: handing the value out here is the only way it can complete
	// the double-submit pair on the POSTs below.
	csrf := s.issueCSRFToken(w)
	if wantsJSON(r) {
		payload := map[string]any{
			"providers":  s.providers.Names(),
			"methods":    []string{"password", "magiclink"},
			"csrf_token": csrf,
		}
		// Branding for custom frontends (Auth0 branding-API parity):
		// a headless UI can render the operator's look without
		// hardcoding it.
		if s.cfg.Brand.Active() || s.cfg.ThemeCSSURL != "" {
			branding := map[string]any{}
			if s.cfg.Brand.LogoURL != "" {
				branding["logo_url"] = s.cfg.Brand.LogoURL
			}
			if s.cfg.Brand.PrimaryColor != "" {
				branding["primary_color"] = s.cfg.Brand.PrimaryColor
			}
			if s.cfg.Brand.PageBG != "" {
				branding["page_background"] = s.cfg.Brand.PageBG
			}
			if s.cfg.Brand.FontURL != "" {
				branding["font_url"] = s.cfg.Brand.FontURL
			}
			if s.cfg.ThemeCSSURL != "" {
				branding["theme_css_url"] = s.cfg.ThemeCSSURL
			}
			payload["branding"] = branding
		}
		writeJSON(w, http.StatusOK, payload)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui.RenderLogin(w, ui.LoginData{
		BaseURL:     s.cfg.BaseURL,
		Providers:   s.providers.Names(),
		Password:    true,
		MagicLink:   true,
		ThemeCSSURL: s.cfg.ThemeCSSURL,
		BrandCSS:    len(s.brandCSS) > 0,
		LogoURL:     s.cfg.Brand.LogoURL,
		Error:       r.URL.Query().Get("error"),
		CSRFToken:   csrf,
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

// handleBrandCSS serves the stylesheet generated from SESAMO_BRAND_*.
// 404 when no branding is configured (the templates only link it when
// it exists, but a hand-typed URL should be honest).
func (s *Server) handleBrandCSS(w http.ResponseWriter, r *http.Request) {
	if len(s.brandCSS) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(s.brandCSS)
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

	s.captureRedirect(w, r)

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
		s.metrics.IncCounter(metricOAuthExchangeErrors)
		s.log.Warn("oauth exchange failed", "provider", name, "err", err)
		s.oauthFail(w, r, codeOAuthFailed, "No pudimos iniciar sesión. Probá de nuevo.")
		return
	}

	res, err := s.users.UpsertByOAuth(r.Context(), profile, s.cfg.Signup != config.SignupDisabled)
	switch {
	case errors.Is(err, user.ErrSignupDisabled):
		if !s.recordAudit(w, r, audit.SignupRejected, "",
			map[string]any{"method": "oauth", "provider": name, "reason": "signup_disabled"}) {
			return
		}
		s.oauthFail(w, r, codeForbidden, "El registro está deshabilitado.")
		return
	case errors.Is(err, user.ErrUserDisabled):
		// The provider vouched for the identity; the deployment refuses
		// the account. Generic login failure, no session, and the real
		// reason stays in the audit trail where it belongs.
		if !s.recordAudit(w, r, audit.LoginFailed, "",
			map[string]any{"method": "oauth", "provider": name, "reason": "user_disabled"}) {
			return
		}
		s.oauthFail(w, r, codeOAuthFailed, "No pudimos iniciar sesión. Probá de nuevo.")
		return
	case err != nil:
		s.log.Error("upsert oauth user", "err", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}

	created, _, err := s.loginTx(r, map[string]any{"method": "oauth", "provider": name},
		func(pgx.Tx) (string, error) { return res.UserID, nil })
	if err != nil {
		s.log.Error("start oauth session", "err", err, "provider", name)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	s.finishLogin(w, r, created)
}

// handlePasswordLogin authenticates email+password. Anti-enumeration:
// identical error + dummy hash work when the user is absent OR disabled.
func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	emailAddr, password := r.FormValue("email"), r.FormValue("password")
	if emailAddr == "" || password == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Email y contraseña requeridos.")
		return
	}

	// Per-identity + per-IP rate limiting (Step 7 enforcement).
	if !s.checkLoginRate(w, r, emailAddr) {
		return
	}

	cred, err := s.users.PasswordCredential(r.Context(), emailAddr)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	if !cred.HasPassword || cred.Disabled {
		// Missing, password-less, or disabled: do dummy work to equalize
		// timing, then return the SAME generic error. A disabled account
		// must be indistinguishable from a nonexistent one, so only the
		// audit reason differs — and that never reaches the client.
		crypto.DummyVerify(password)
		reason, actor := "unknown_user", ""
		if cred.Disabled {
			reason, actor = "user_disabled", cred.UserID
		}
		if !s.recordAudit(w, r, audit.LoginFailed, actor,
			map[string]any{"method": "password", "email": emailAddr, "reason": reason}) {
			return
		}
		writeError(w, http.StatusUnauthorized, codeInvalidCredentials, "Email o contraseña incorrectos.")
		return
	}

	valid, needsRehash, err := crypto.VerifyPassword(password, cred.Hash)
	if err != nil || !valid {
		if !s.recordAudit(w, r, audit.LoginFailed, cred.UserID,
			map[string]any{"method": "password", "email": emailAddr, "reason": "bad_password"}) {
			return
		}
		writeError(w, http.StatusUnauthorized, codeInvalidCredentials, "Email o contraseña incorrectos.")
		return
	}

	// Lazy migration: re-hash bcrypt (Auth0 import) to Argon2id.
	if needsRehash {
		if newHash, err := crypto.HashPassword(password); err == nil {
			_ = s.users.SetPassword(r.Context(), cred.UserID, newHash)
		}
	}

	created, _, err := s.loginTx(r, map[string]any{"method": "password"},
		func(pgx.Tx) (string, error) { return cred.UserID, nil })
	if err != nil {
		s.log.Error("start password session", "err", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	s.finishLogin(w, r, created)
}

// handleSignup creates a password user and sends a verification email.
func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if s.cfg.Signup == config.SignupDisabled {
		// One stable response for every caller: the branch never touches
		// the database, so it cannot leak whether an account exists.
		if !s.recordAudit(w, r, audit.SignupRejected, "",
			map[string]any{"method": "password", "reason": "signup_disabled"}) {
			return
		}
		writeError(w, http.StatusForbidden, codeForbidden, "El registro está deshabilitado.")
		return
	}
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
	err = s.auditedTx(r.Context(), s.clientIP(r), func(tx pgx.Tx) (auditRecord, error) {
		if err := s.users.CreateWithPasswordTx(r.Context(), tx, id, emailAddr, hash); err != nil {
			return auditRecord{}, err
		}
		// The verification mail is queued in the same transaction as the
		// user row: a signup that answers "verification_sent" has a job
		// that will be delivered, and a rolled-back signup leaves no mail
		// promising an account that does not exist.
		if err := s.queueOneTimeLinkTx(r.Context(), tx, id, emailAddr, email.PurposeVerify,
			"/verify", "Verificá tu email", 24*time.Hour); err != nil {
			return auditRecord{}, err
		}
		return auditRecord{event: audit.Signup, actor: id, detail: map[string]any{"email": emailAddr}}, nil
	})
	if err != nil {
		// Three very different failures collapse into one response on
		// purpose. A duplicate email must look like a fresh signup
		// (anti-enumeration), and a strict-mode audit outage or a failed
		// enqueue must look the same as that: a 500 here would only ever
		// fire for emails that DID insert, turning the outage into an
		// existence oracle. Same degradation /reset and /magiclink accept.
		var auditErr auditWriteError
		if errors.As(err, &auditErr) {
			s.log.Warn("signup rolled back by strict audit failure (masked as 200)", "err", err)
		} else {
			s.log.Info("signup conflict or error (masked)", "err", err)
			s.metrics.IncCounter(metricEmailQueueErrors)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "verification_sent"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "verification_sent"})
}

// handleLogout invalidates the session and clears the cookie. POST-only
// plus a CSRF token. An optional redirect_to form value, validated
// against the same origin allowlist as login, lets a consuming app land
// the user back on its own signed-out page instead of Sésamo's root.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	if token := cookieValue(r, s.cfg.CookieName); token != "" {
		err := s.auditedTx(r.Context(), s.clientIP(r), func(tx pgx.Tx) (auditRecord, error) {
			uid, err := s.sessions.RevokeTx(r.Context(), tx, token)
			if err != nil {
				return auditRecord{}, err
			}
			if uid == "" {
				// Stale or forged cookie: nothing was revoked, so there
				// is no event to evidence.
				return auditRecord{}, nil
			}
			return auditRecord{event: audit.Logout, actor: uid}, nil
		})
		if err != nil {
			// The session is still alive, so the cookie stays: clearing it
			// would strand a live session with no way for its owner to
			// reach it again. The client can retry.
			s.log.Error("logout", "err", err)
			writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
			return
		}
	}
	s.clearSessionCookie(w)
	target := s.safeRedirectTarget(r.FormValue("redirect_to"))
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "logged_out", "redirect_to": target,
		})
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// renderMessage writes an outcome page (message.html) with the brand
// chrome and the given HTTP status. Browser-facing counterpart of the
// JSON status objects.
func (s *Server) renderMessage(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := ui.RenderMessage(w, ui.MessageData{
		BaseURL:     s.cfg.BaseURL,
		Title:       title,
		Body:        body,
		ThemeCSSURL: s.cfg.ThemeCSSURL,
		BrandCSS:    len(s.brandCSS) > 0,
		LogoURL:     s.cfg.Brand.LogoURL,
	}); err != nil {
		s.log.Error("render message", "err", err)
	}
}

// handleResetRequestPage renders the "request a reset link" form. The
// login page links here ("¿Olvidaste tu contraseña?").
func (s *Server) handleResetRequestPage(w http.ResponseWriter, r *http.Request) {
	csrf := s.issueCSRFToken(w)
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{
			"method": "POST", "fields": []string{"email"}, "csrf_token": csrf,
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui.RenderResetRequest(w, ui.ResetRequestData{
		BaseURL:     s.cfg.BaseURL,
		ThemeCSSURL: s.cfg.ThemeCSSURL,
		BrandCSS:    len(s.brandCSS) > 0,
		LogoURL:     s.cfg.Brand.LogoURL,
		CSRFToken:   csrf,
	}); err != nil {
		s.log.Error("render reset request", "err", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
	}
}

// handleResetConfirmPage renders the new-password form for the token in
// the emailed link. The token is NOT consumed here — only the POST
// spends it, so previewing the page can't burn the single use.
func (s *Server) handleResetConfirmPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	csrf := s.issueCSRFToken(w)
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{
			"method": "POST", "fields": []string{"token", "password"}, "csrf_token": csrf,
		})
		return
	}
	if token == "" {
		s.renderMessage(w, http.StatusBadRequest, "Enlace inválido",
			"El enlace no es válido. Pedí uno nuevo desde \"¿Olvidaste tu contraseña?\".")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui.RenderResetConfirm(w, ui.ResetConfirmData{
		BaseURL:     s.cfg.BaseURL,
		ThemeCSSURL: s.cfg.ThemeCSSURL,
		BrandCSS:    len(s.brandCSS) > 0,
		LogoURL:     s.cfg.Brand.LogoURL,
		Token:       token,
		CSRFToken:   csrf,
	}); err != nil {
		s.log.Error("render reset confirm", "err", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
	}
}

// handleResetRequest always returns 200 to avoid revealing whether the
// email exists. If it does, a reset link is sent.
func (s *Server) handleResetRequest(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
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
		// Evidence, token and queued mail share one transaction. On any
		// failure — strict-mode audit outage included — nothing is
		// queued and the response stays the generic 200: a 500 only for
		// existing accounts would turn an outage into an enumeration
		// oracle.
		if err := s.auditedTx(r.Context(), s.clientIP(r), func(tx pgx.Tx) (auditRecord, error) {
			if err := s.queueOneTimeLinkTx(r.Context(), tx, u.ID, emailAddr, email.PurposeReset,
				"/reset/confirm", "Restablecé tu contraseña", 15*time.Minute); err != nil {
				return auditRecord{}, err
			}
			return auditRecord{event: audit.ResetRequested, actor: u.ID}, nil
		}); err != nil {
			s.metrics.IncCounter(metricEmailQueueErrors)
			s.log.Warn("reset link not queued (masked as 200)", "err", err)
		}
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "reset_sent"})
		return
	}
	s.renderMessage(w, http.StatusOK, "Revisá tu email",
		"Si existe una cuenta con ese email, te enviamos un enlace para restablecer la contraseña.")
}

// handleResetConfirm consumes a reset token and sets the new password.
// Spending the token, storing the hash, killing every existing session,
// and recording the evidence are one transaction: a partial reset would
// either leave the user locked out of a burned link or leave the old
// sessions alive after telling them otherwise.
func (s *Server) handleResetConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	token, password := r.FormValue("token"), r.FormValue("password")
	if token == "" || len(password) < 8 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Token y contraseña de 8+ caracteres requeridos.")
		return
	}
	// Hash before opening the transaction: Argon2id is ~100ms of CPU and
	// must not hold a pooled connection. Side benefit — every request
	// pays it, so response time no longer distinguishes a valid token
	// from a spent one.
	hash, err := crypto.HashPassword(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}

	err = s.auditedTx(r.Context(), s.clientIP(r), func(tx pgx.Tx) (auditRecord, error) {
		userID, err := s.tokens.ConsumeTx(r.Context(), tx, token, email.PurposeReset)
		if err != nil {
			return auditRecord{}, err
		}
		if err := s.users.SetPasswordTx(r.Context(), tx, userID, hash); err != nil {
			return auditRecord{}, err
		}
		// Reset implies privilege change: kill all existing sessions.
		if err := s.sessions.RevokeAllForUserTx(r.Context(), tx, userID); err != nil {
			return auditRecord{}, err
		}
		return auditRecord{event: audit.ResetCompleted, actor: userID,
			detail: map[string]any{"sessions_revoked": "all"}}, nil
	})
	if errors.Is(err, email.ErrInvalidToken) {
		if wantsJSON(r) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Token inválido o expirado.")
			return
		}
		s.renderMessage(w, http.StatusBadRequest, "Enlace inválido o vencido",
			"El enlace ya fue usado o expiró. Pedí uno nuevo desde \"¿Olvidaste tu contraseña?\".")
		return
	}
	if err != nil {
		// Nothing was applied and the token was not spent, so the same
		// link works on retry.
		s.log.Error("reset confirm", "err", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "password_reset"})
		return
	}
	s.renderMessage(w, http.StatusOK, "Contraseña actualizada",
		"Tu contraseña fue cambiada y cerramos todas tus sesiones. Iniciá sesión de nuevo.")
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
		if wantsJSON(r) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Token inválido o expirado.")
			return
		}
		s.renderMessage(w, http.StatusBadRequest, "Enlace inválido o vencido",
			"El enlace de verificación ya fue usado o expiró.")
		return
	}
	if err := s.users.MarkEmailVerified(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	if !s.recordAudit(w, r, audit.EmailVerified, userID, nil) {
		return
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "email_verified"})
		return
	}
	s.renderMessage(w, http.StatusOK, "Email verificado",
		"Tu email quedó verificado. Ya podés iniciar sesión.")
}

// handleMagicLinkRequest emails a one-time login link. Always 200.
func (s *Server) handleMagicLinkRequest(w http.ResponseWriter, r *http.Request) {
	if !s.checkCSRF(w, r) {
		return
	}
	emailAddr := r.FormValue("email")
	if emailAddr == "" {
		if wantsJSON(r) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Email requerido.")
			return
		}
		// Browser: the login form posted without an email — bounce back
		// with the error banner instead of raw JSON.
		http.Redirect(w, r, "/login?error=email_required", http.StatusFound)
		return
	}
	if !s.checkLoginRate(w, r, emailAddr) {
		return
	}
	u, err := s.users.ByEmail(r.Context(), emailAddr)
	// A disabled account is treated as nonexistent: no link is minted, so
	// the kill switch cannot be worked around by asking for a fresh one,
	// and the response stays identical either way.
	if err == nil && u != nil && !u.Disabled {
		// Same enumeration-safe degradation as /reset above: evidence,
		// token and queued mail commit together or not at all, and the
		// caller cannot tell which happened.
		if err := s.auditedTx(r.Context(), s.clientIP(r), func(tx pgx.Tx) (auditRecord, error) {
			if err := s.queueOneTimeLinkTx(r.Context(), tx, u.ID, emailAddr, email.PurposeMagicLink,
				"/magiclink/confirm", "Tu enlace de acceso", 15*time.Minute); err != nil {
				return auditRecord{}, err
			}
			return auditRecord{event: audit.MagicLinkRequest, actor: u.ID}, nil
		}); err != nil {
			s.metrics.IncCounter(metricEmailQueueErrors)
			s.log.Warn("magic link not queued (masked as 200)", "err", err)
		}
	}
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "magiclink_sent"})
		return
	}
	s.renderMessage(w, http.StatusOK, "Revisá tu email",
		"Si existe una cuenta con ese email, te enviamos un enlace de acceso.")
}

// handleMagicLinkConfirm consumes a magic link and starts a session.
// Spending the token, verifying the email, creating the session and
// recording the evidence are one transaction, so a failure anywhere
// leaves the link usable instead of burning it for nothing.
func (s *Server) handleMagicLinkConfirm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Token requerido.")
		return
	}
	created, _, err := s.loginTx(r, map[string]any{"method": "magiclink"},
		func(tx pgx.Tx) (string, error) {
			userID, err := s.tokens.ConsumeTx(r.Context(), tx, token, email.PurposeMagicLink)
			if err != nil {
				return "", err
			}
			// The kill switch outranks a valid link. The check shares the
			// token's transaction, so refusing here un-spends it: the
			// link still works if the account is re-enabled in time.
			disabled, err := s.users.DisabledTx(r.Context(), tx, userID)
			if err != nil {
				return "", err
			}
			if disabled {
				return "", user.ErrUserDisabled
			}
			// A magic link also verifies the email (proof of inbox control).
			if err := s.users.MarkEmailVerifiedTx(r.Context(), tx, userID); err != nil {
				return "", err
			}
			return userID, nil
		})
	if errors.Is(err, email.ErrInvalidToken) || errors.Is(err, user.ErrUserDisabled) {
		// One answer for both: "this link does not work". Splitting them
		// would tell whoever holds the link that the account exists but
		// is disabled.
		if wantsJSON(r) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Enlace inválido o expirado.")
			return
		}
		s.renderMessage(w, http.StatusBadRequest, "Enlace inválido o vencido",
			"El enlace de acceso ya fue usado o expiró. Pedí uno nuevo desde la pantalla de inicio de sesión.")
		return
	}
	if err != nil {
		s.log.Error("magiclink confirm", "err", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	s.finishLogin(w, r, created)
}

// loginTx runs the flow-specific work that identifies the user, inserts
// the session, and records the login evidence — all under one
// transaction (see auditedTx for the atomicity contract). resolve runs
// inside that transaction, so a flow that spends a one-time token
// un-spends it when anything downstream fails.
func (s *Server) loginTx(r *http.Request, detail map[string]any,
	resolve func(pgx.Tx) (string, error),
) (created session.Created, userID string, err error) {
	ua := r.UserAgent()
	ip := s.clientIP(r)
	err = s.auditedTx(r.Context(), ip, func(tx pgx.Tx) (auditRecord, error) {
		var err error
		if userID, err = resolve(tx); err != nil {
			return auditRecord{}, err
		}
		if created, err = s.sessions.CreateTx(r.Context(), tx, session.CreateInput{
			UserID: userID, UserAgent: &ua, IPFirst: &ip,
		}); err != nil {
			return auditRecord{}, err
		}
		return auditRecord{event: audit.LoginSuccess, actor: userID, detail: detail}, nil
	})
	return created, userID, err
}

// finishLogin emits the session cookie, rotates the CSRF token, and
// either returns JSON (headless) or redirects to the post-login target.
// The target comes from an explicit redirect_to form value (headless
// callers) or the transient cookie captured at GET /login / OAuth start;
// both go through the same allowlist validation on read.
//
// Rotating the CSRF token here is deliberate: a value planted before
// authentication must not survive the privilege change, and the fresh
// one is what a headless client needs for POST /logout (it cannot read
// the HttpOnly cookie itself).
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, created session.Created) {
	s.setSessionCookie(w, created.Token, created.ExpiresAt)
	csrf := s.issueCSRFToken(w)

	raw := r.FormValue("redirect_to")
	if raw == "" {
		raw = cookieValue(r, cookiePostLogin)
	}
	target := s.safeRedirectTarget(raw)
	s.clearTransient(w, cookiePostLogin)

	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "authenticated", "redirect_to": target, "csrf_token": csrf,
		})
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// sendBeforeMargin keeps the worker from delivering a link that is about
// to expire: a user who receives a reset mail whose token dies a few
// seconds later experiences a broken product, not a security feature.
const sendBeforeMargin = time.Minute

// queueOneTimeLinkTx mints a one-time token and queues the email that
// carries it, both inside the caller's transaction.
//
// This is the atomicity the outbox exists for: a rollback leaves neither
// a token nobody was told about nor a queued link to a token that does
// not exist. Delivery itself happens outside the request, in the worker,
// so a provider outage no longer loses the mail — and no longer holds a
// pooled connection while an external API times out.
func (s *Server) queueOneTimeLinkTx(ctx context.Context, tx pgx.Tx, userID, to string,
	purpose email.Purpose, path, subject string, ttl time.Duration,
) error {
	token, tokenID, err := s.tokens.IssueTx(ctx, tx, userID, purpose, ttl)
	if err != nil {
		return err
	}
	link := s.cfg.BaseURL + path + "?token=" + token
	body := subject + ":\n\n" + link + "\n\nEste enlace expira pronto y se usa una sola vez."
	return s.outbox.QueueTx(ctx, tx, email.QueueInput{
		UserID:     userID,
		TokenID:    tokenID,
		To:         to,
		From:       s.cfg.EmailFrom,
		Subject:    subject,
		Body:       body,
		Purpose:    purpose,
		Provider:   s.cfg.EmailProvider,
		SendBefore: time.Now().Add(ttl - sendBeforeMargin),
	})
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

// ── action + evidence atomicity ───────────────────────────────────────

// auditRecord is the evidence an auditedTx action produced. A zero event
// means "nothing happened worth recording" and no row is written.
type auditRecord struct {
	event  audit.Event
	actor  string
	detail map[string]any
}

// auditWriteError wraps a failure of the audit half of an auditedTx.
// Anti-enumeration callers need to tell it apart from a failure of the
// action: both must produce the same response to the client, but only
// one of them deserves an operator-visible warning.
type auditWriteError struct{ err error }

func (e auditWriteError) Error() string { return "audit write failed: " + e.err.Error() }
func (e auditWriteError) Unwrap() error { return e.err }

// auditedTx performs a database action and records its evidence with the
// atomicity the deployment asked for. The action always runs in one
// transaction, so multi-statement flows (spend token, set password,
// revoke sessions) can no longer half-apply.
//
// Strict mode (SESAMO_AUDIT_STRICT) puts the evidence row in that same
// transaction: either both land or neither does — no action without
// evidence, and no evidence for an action that was rolled back. The
// caller's error response therefore describes a state the client can
// safely retry.
//
// Best-effort mode (the default) commits the action and only then
// attempts the evidence, swallowing and logging failure exactly as
// before: availability of the auth path outranks audit completeness. The
// two modes cannot share one path — Postgres aborts a transaction on any
// failed statement, so "ignore the audit error" is only expressible
// outside the transaction.
func (s *Server) auditedTx(ctx context.Context, ip string, action func(pgx.Tx) (auditRecord, error)) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rec, err := action(tx)
	if err != nil {
		return err
	}
	if s.cfg.AuditStrict && rec.event != "" {
		if err := s.audit.RecordTx(ctx, tx, rec.event, rec.actor, ip, rec.detail); err != nil {
			s.metrics.IncCounter(metricAuditWriteErrors)
			return auditWriteError{err: err}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if !s.cfg.AuditStrict && rec.event != "" {
		// Record swallows its own failure here (best-effort mode), so the
		// discarded error is the documented contract, not an oversight.
		_ = s.audit.Record(ctx, rec.event, rec.actor, ip, rec.detail)
	}
	return nil
}
