package http

import (
	"net/http"

	"github.com/jcibernet/sesamo/internal/crypto"
)

func (s *Server) registerAdmin() {
	s.mux.HandleFunc("GET /v1/admin/users/{id}", s.requireAdminKey(s.handleAdminGetUser))
	s.mux.HandleFunc("POST /v1/admin/users/{id}/revoke-sessions", s.requireAdminKey(s.handleAdminRevokeUserSessions))
}

// handleAdminGetUser returns a single user by id.
func (s *Server) handleAdminGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := s.users.ByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, codeNotFound, "Usuario no encontrado.")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// handleAdminRevokeUserSessions force-logs-out every session of a user.
func (s *Server) handleAdminRevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.sessions.RevokeAllForUser(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sessions_revoked"})
}

// requireAdminKey guards admin endpoints with a constant-time bearer
// check against SESAMO_ADMIN_API_KEY.
func (s *Server) requireAdminKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminAPIKey == "" {
			writeError(w, http.StatusServiceUnavailable, codeForbidden, "Admin API no configurada.")
			return
		}
		got := bearerToken(r)
		if got == "" || !crypto.SafeEqual([]byte(got), []byte(s.cfg.AdminAPIKey)) {
			writeError(w, http.StatusUnauthorized, codeUnauthorized, "Clave de admin inválida.")
			return
		}
		next(w, r)
	}
}
