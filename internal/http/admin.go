package http

import (
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/jcibernet/sesamo/internal/audit"
	"github.com/jcibernet/sesamo/internal/crypto"
)

func (s *Server) registerAdmin() {
	s.mux.HandleFunc("GET /v1/admin/users/{id}", s.requireAdminKey(s.handleAdminGetUser))
	s.mux.HandleFunc("POST /v1/admin/users/{id}/revoke-sessions", s.requireAdminKey(s.handleAdminRevokeUserSessions))
	s.mux.HandleFunc("POST /v1/admin/users/{id}/disable", s.requireAdminKey(s.handleAdminSetUserDisabled))
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
	if !s.recordAudit(w, r, audit.SessionsRevokedAll, id, map[string]any{"via": "admin"}) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sessions_revoked"})
}

// handleAdminSetUserDisabled flips the account kill switch. The `disabled`
// form/JSON field carries the target state, so the same endpoint enables
// and disables — an operator undoing a mistake should not have to find a
// second route.
//
// Disabling also revokes every live session: the flag alone only stops
// the NEXT validation of each token, and a live session with a cached
// gateway decision could outlive the decision to cut the account off.
func (s *Server) handleAdminSetUserDisabled(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	raw := r.FormValue("disabled")
	disabled, err := strconv.ParseBool(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest,
			`El campo "disabled" debe ser "true" o "false".`)
		return
	}
	if _, err := s.users.ByID(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, codeNotFound, "Usuario no encontrado.")
		return
	}

	event := audit.UserEnabled
	if disabled {
		event = audit.UserDisabled
	}
	err = s.auditedTx(r.Context(), s.clientIP(r), func(tx pgx.Tx) (auditRecord, error) {
		if err := s.users.SetDisabledTx(r.Context(), tx, id, disabled); err != nil {
			return auditRecord{}, err
		}
		if disabled {
			if err := s.sessions.RevokeAllForUserTx(r.Context(), tx, id); err != nil {
				return auditRecord{}, err
			}
		}
		return auditRecord{event: event, actor: id,
			detail: map[string]any{"via": "admin", "sessions_revoked": disabled}}, nil
	})
	if err != nil {
		s.log.Error("admin set user disabled", "err", err, "disabled", disabled)
		writeError(w, http.StatusInternalServerError, codeInternal, "Error interno.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "updated", "user_id": id, "disabled": disabled,
	})
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
