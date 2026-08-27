package http

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jcibernet/sesamo/internal/crypto"
)

// session cookie helpers. The session cookie carries the raw opaque
// token; it is HttpOnly + SameSite=Lax, and Secure in production.

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    token,
		Path:     "/",
		Domain:   s.cfg.CookieDomain, // empty => host-only cookie (default)
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	// Domain must match the one used when setting, or the browser will
	// not clear the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// short-lived transient cookies for the OAuth round trip: state + PKCE
// verifier + optional post-login redirect.

const (
	cookieOAuthState  = "sesamo_oauth_state"
	cookiePKCE        = "sesamo_pkce"
	cookiePostLogin   = "sesamo_post_login"
	cookieCSRF        = "sesamo_csrf"
	oauthCookieMaxAge = 5 * 60 // 5 minutes
	// The post-login target outlives the OAuth transients because email
	// flows (magic link) take longer than an OAuth bounce: the emailed
	// token itself lives 15 minutes, so the destination must too.
	postLoginCookieMaxAge = 15 * 60
	// csrfCookieMaxAge (1 hour) outlives a slow form fill and a password
	// manager round trip without letting a token linger for a whole
	// session. Past it the form POST fails closed and the user reloads.
	csrfCookieMaxAge = 60 * 60
)

func (s *Server) setTransient(w http.ResponseWriter, name, value string) {
	s.setTransientTTL(w, name, value, oauthCookieMaxAge)
}

func (s *Server) setTransientTTL(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearTransient(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ── CSRF for session-mutating form POSTs ─────────────────────────────
//
// The session cookie is SameSite=Lax, which blocks cross-site POSTs in
// current browsers — but SameSite is a browser default, not a boundary
// Sésamo controls: clients that predate it, gateways that rewrite the
// attribute, and same-site-different-origin subdomains all weaken it,
// and it says nothing at all about a request forged by a page on an
// allowlisted sibling origin. The boundary is the double-submit pair
// below: a 256-bit value that must appear in BOTH the transient cookie
// and the request body/header, compared in constant time.

const (
	// csrfField is the form field carrying the request half of the pair;
	// csrfHeader is its headless equivalent for fetch/XHR callers.
	csrfField  = "csrf_token"
	csrfHeader = "X-CSRF-Token"
)

// issueCSRFToken mints a token, sets the transient cookie, and returns
// the value so the caller can embed it in the form or JSON payload it is
// about to render. Called on every GET that hands out a form and on
// session creation, so the token rotates on privilege change and a
// value planted pre-authentication never carries into a session.
func (s *Server) issueCSRFToken(w http.ResponseWriter) string {
	token := crypto.GenerateToken()
	s.setTransientTTL(w, cookieCSRF, token, csrfCookieMaxAge)
	return token
}

// checkCSRF enforces the double-submit pair. It writes the failure
// response itself and returns false, so callers read:
//
//	if !s.checkCSRF(w, r) { return }
//
// Both halves must be present: an attacker's cross-site form can forge
// the body but cannot read the cookie, and a request with no cookie at
// all (a stripped or expired transient) is indistinguishable from that,
// so it fails closed too.
func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	// Parse the form here, not just in FormValue below: an unparseable
	// body must answer 400 (bad request), not collapse into "missing
	// CSRF token" (403). The body limit turns an oversized POST into
	// exactly this parse error, and that boundary was 400 long before
	// CSRF existed — Threat19 pins it.
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest,
			"Formulario ilegible.")
		return false
	}
	cookie := cookieValue(r, cookieCSRF)
	sent := r.FormValue(csrfField)
	if sent == "" {
		sent = r.Header.Get(csrfHeader)
	}
	if cookie != "" && sent != "" && crypto.SafeEqual([]byte(cookie), []byte(sent)) {
		return true
	}
	// 403 in both representations. A redirect would be friendlier for the
	// benign case (a form left open past csrfCookieMaxAge) but it would
	// report success for a rejected mutation; the status code is the
	// stable part of this contract, so the browser gets a real 403 page
	// with a way back instead of a 302.
	if wantsJSON(r) {
		writeError(w, http.StatusForbidden, codeCSRFFailed,
			"Token CSRF inválido o ausente.")
		return false
	}
	s.renderMessage(w, http.StatusForbidden, "No pudimos procesar el formulario",
		"El formulario venció o no viene de esta página. Volvé a cargarla y probá de nuevo.")
	return false
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// captureRedirect persists a validated ?redirect_to= target in the
// post-login cookie so every flow that ends in startSessionAndRedirect
// (password, OAuth, magic link) returns to it. The target is validated
// on write AND on read: a cookie is attacker-writable in shared-domain
// setups, so the read side never trusts it.
func (s *Server) captureRedirect(w http.ResponseWriter, r *http.Request) {
	if raw := r.URL.Query().Get("redirect_to"); raw != "" {
		s.setTransientTTL(w, cookiePostLogin, s.safeRedirectTarget(raw), postLoginCookieMaxAge)
	}
}

// safeRedirectTarget returns a redirect target that cannot leave the
// deployment's trust boundary: either an internal path or an absolute
// URL whose origin exactly matches one entry of SESAMO_REDIRECT_ORIGINS.
// Everything else — protocol-relative, backslash tricks, userinfo,
// lookalike hosts, unlisted ports, non-http(s) schemes — collapses to "/".
func (s *Server) safeRedirectTarget(raw string) string {
	return safeRedirectTarget(s.cfg.RedirectOrigins, raw)
}

func safeRedirectTarget(allowedOrigins []string, raw string) string {
	if raw == "" {
		return "/"
	}
	// WHATWG URL parsing strips ASCII tab/newline entirely, so a target
	// like "/\t/evil.com" reaches the browser as "//evil.com". Any control
	// character is therefore smuggling, never a legitimate destination.
	for i := range len(raw) {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "/"
		}
	}
	if raw[0] == '/' {
		return safeInternalPath(raw)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "/"
	}
	// Hosts are case-insensitive (RFC 3986); the allowlist is stored
	// lowercase, so compare lowercase.
	origin := u.Scheme + "://" + strings.ToLower(u.Host)
	for _, allowed := range allowedOrigins {
		if origin == allowed {
			// Rebuild scheme://host + path?query and drop the fragment:
			// the redirect carries exactly what was validated, nothing
			// smuggled through URL re-serialization quirks.
			target := origin + safeInternalPath(u.EscapedPath())
			if u.RawQuery != "" {
				target += "?" + u.RawQuery
			}
			return target
		}
	}
	return "/"
}

// safeInternalPath returns the path if it is a safe internal redirect
// target ("/foo", not "//evil.com", "/\evil.com", or "https://evil.com"),
// else "/".
func safeInternalPath(p string) string {
	if len(p) == 0 || p[0] != '/' {
		return "/"
	}
	// Protocol-relative ("//host") and backslash ("/\host" — browsers
	// normalize \ to /) would escape the origin: both are open redirects.
	if len(p) >= 2 && (p[1] == '/' || p[1] == '\\') {
		return "/"
	}
	return p
}
