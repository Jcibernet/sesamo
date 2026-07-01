package http

import (
	"net/http"
	"strings"

	"github.com/jcibernet/sesamo/internal/crypto"
	"github.com/jcibernet/sesamo/internal/session"
)

func (s *Server) registerService() {
	s.mux.HandleFunc("POST /v1/introspect", s.requireServiceToken(s.handleIntrospect))
	s.mux.HandleFunc("POST /v1/sessions/revoke", s.requireServiceToken(s.handleSessionRevoke))
}

// introspectResponse is the S2S session check result. Shaped after RFC
// 7662 (OAuth token introspection): "active" is the one field every
// caller must check.
type introspectResponse struct {
	Active        bool           `json:"active"`
	UserID        string         `json:"user_id,omitempty"`
	Email         string         `json:"email,omitempty"`
	EmailVerified bool           `json:"email_verified,omitempty"`
	Name          *string        `json:"name,omitempty"`
	ExpiresAt     int64          `json:"expires_at,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// handleIntrospect validates an opaque session token presented by a
// trusted backend and returns the resolved identity. This is the hot
// path; it must be a single indexed lookup (Step 9 load test target:
// p50<5ms, p99<20ms).
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	token := introspectToken(r)
	if token == "" {
		writeJSON(w, http.StatusOK, introspectResponse{Active: false})
		return
	}

	res, err := s.sessions.Validate(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	if res.Kind != session.KindValid || res.User == nil {
		writeJSON(w, http.StatusOK, introspectResponse{Active: false})
		return
	}

	// If rolling renewal extended the session, surface the new expiry so
	// a gateway can refresh its cached cookie if it manages one.
	if res.Renewed {
		w.Header().Set("X-Session-Renewed", "1")
	}

	writeJSON(w, http.StatusOK, introspectResponse{
		Active:        true,
		UserID:        res.User.ID,
		Email:         res.User.Email,
		EmailVerified: res.User.EmailVerified,
		Name:          res.User.Name,
		ExpiresAt:     res.ExpiresAt.Unix(),
		Metadata:      res.User.Metadata,
	})
}

// handleSessionRevoke lets a backend force-logout a session by token.
func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	token := introspectToken(r)
	if token == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Falta el token de sesión.")
		return
	}
	if err := s.sessions.Revoke(r.Context(), token); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// introspectToken pulls the session token from the JSON/form body field
// "token" or, failing that, a sesamo session cookie forwarded by a gateway.
func introspectToken(r *http.Request) string {
	if t := strings.TrimSpace(r.FormValue("token")); t != "" {
		return t
	}
	if c, err := r.Cookie("sid"); err == nil {
		return c.Value
	}
	return ""
}

// requireServiceToken guards S2S endpoints with a constant-time bearer
// check against SESAMO_SERVICE_TOKEN.
func (s *Server) requireServiceToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.ServiceToken == "" {
			writeError(w, http.StatusServiceUnavailable, codeForbidden, "Introspección no configurada.")
			return
		}
		got := bearerToken(r)
		if got == "" || !crypto.SafeEqual([]byte(got), []byte(s.cfg.ServiceToken)) {
			writeError(w, http.StatusUnauthorized, codeUnauthorized, "Token de servicio inválido.")
			return
		}
		next(w, r)
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}
