package http

import (
	"net/http"
	"strconv"

	"github.com/jcibernet/sesamo/internal/ratelimit"
)

// Login/credential rate limits. These guard every credential-accepting
// endpoint (password login, reset request, magic-link request) against
// brute force and enumeration probing. We limit on BOTH the client IP
// and the target identity so neither a single IP nor a single account
// can be hammered.
var (
	loginIPRule       = ratelimit.Rule{Capacity: 20, RefillPerSec: 20.0 / 60.0} // ~20/min/IP
	loginIdentityRule = ratelimit.Rule{Capacity: 5, RefillPerSec: 5.0 / 60.0}   // ~5/min/identity
)

// checkLoginRate enforces the IP + identity buckets. On limit it writes a
// 429 with Retry-After and returns false so the caller stops. Failures of
// the limiter backend fail OPEN (allow) to avoid locking everyone out on
// a transient DB hiccup — credential checks themselves remain safe.
func (s *Server) checkLoginRate(w http.ResponseWriter, r *http.Request, identity string) bool {
	ip := clientIP(r)
	if ok := s.allow(w, r, "login_ip:"+ip, loginIPRule); !ok {
		return false
	}
	if ok := s.allow(w, r, "login_id:"+identity, loginIdentityRule); !ok {
		return false
	}
	return true
}

func (s *Server) allow(w http.ResponseWriter, r *http.Request, key string, rule ratelimit.Rule) bool {
	allowed, retry, err := s.limiter.Allow(r.Context(), key, rule)
	if err != nil {
		s.log.Warn("rate limiter error (failing open)", "err", err)
		return true
	}
	if !allowed {
		secs := int(retry.Seconds())
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeError(w, http.StatusTooManyRequests, codeRateLimited, "Demasiados intentos. Probá más tarde.")
		return false
	}
	return true
}
