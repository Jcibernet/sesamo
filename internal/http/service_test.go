package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jcibernet/sesamo/internal/config"
)

func TestIntrospectTokenUsesConfiguredCookieName(t *testing.T) {
	s := &Server{cfg: &config.Config{CookieName: "acme_session"}}
	r := httptest.NewRequest(http.MethodPost, "/v1/introspect", nil)
	r.AddCookie(&http.Cookie{Name: "acme_session", Value: "opaque-token"})

	if got := s.introspectToken(r); got != "opaque-token" {
		t.Fatalf("introspectToken() = %q, want configured cookie token", got)
	}
}
