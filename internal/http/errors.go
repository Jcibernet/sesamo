package http

import (
	"encoding/json"
	"net/http"
	"strings"
)

// apiError is the single, consistent error shape for all JSON responses.
// Codes are stable and machine-readable; messages are human-facing and
// deliberately generic to avoid enumeration leaks.
type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Stable error codes.
const (
	codeInvalidCredentials = "invalid_credentials"
	codeInvalidRequest     = "invalid_request"
	codeRateLimited        = "rate_limited"
	codeUnauthorized       = "unauthorized"
	codeForbidden          = "forbidden"
	codeNotFound           = "not_found"
	codeInternal           = "internal_error"
	codeStateMismatch      = "state_mismatch"
	codeOAuthFailed        = "oauth_failed"
	codeCSRFFailed         = "csrf_failed"
)

// writeError emits a JSON apiError with the given status and code.
func writeError(w http.ResponseWriter, status int, code, message string) {
	var e apiError
	e.Error.Code = code
	e.Error.Message = message
	writeJSON(w, status, e)
}

// writeJSON marshals v as JSON with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// wantsJSON reports whether the client prefers a JSON response (headless
// mode) over an HTML redirect. True when Accept contains application/json
// or the ?mode=json query is present.
func wantsJSON(r *http.Request) bool {
	if r.URL.Query().Get("mode") == "json" {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}
