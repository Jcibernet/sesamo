package http

import (
	"net/http"
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
)

func (s *Server) setTransient(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   oauthCookieMaxAge,
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

// safeInternalPath returns the path if it is a safe internal redirect
// target ("/foo", not "//evil.com" or "https://evil.com"), else "/".
func safeInternalPath(p string) string {
	if len(p) == 0 || p[0] != '/' {
		return "/"
	}
	if len(p) >= 2 && p[1] == '/' { // protocol-relative => open redirect
		return "/"
	}
	return p
}
