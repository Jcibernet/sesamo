package http

import (
	"net/http"
	"net/url"
	"strings"
	"time"
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
	oauthCookieMaxAge = 5 * 60 // 5 minutes
	// The post-login target outlives the OAuth transients because email
	// flows (magic link) take longer than an OAuth bounce: the emailed
	// token itself lives 15 minutes, so the destination must too.
	postLoginCookieMaxAge = 15 * 60
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
