package http

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jcibernet/sesamo/internal/config"
)

func TestHeadlessPasswordLoginRedirectContract(t *testing.T) {
	h := newRedirectHarness(t)
	emailAddr := uniqueEmail("headlessredirect")
	h.signup(emailAddr, "correct-horse-headless")

	for _, tc := range []struct {
		name   string
		target string
		want   string
	}{
		{
			name:   "allowlisted external origin",
			target: "http://127.0.0.1:8010/paper?tab=positions",
			want:   "http://127.0.0.1:8010/paper?tab=positions",
		},
		{
			name:   "unlisted external origin",
			target: "https://evil.example/paper",
			want:   "/",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, body := h.postJSON(h.client(), "/login", url.Values{
				"email":       {emailAddr},
				"password":    {"correct-horse-headless"},
				"redirect_to": {tc.target},
			})
			if res.StatusCode != http.StatusOK {
				t.Fatalf("POST /login: status = %d, body = %s", res.StatusCode, body)
			}
			if !strings.Contains(body, `"redirect_to":"`+tc.want+`"`) {
				t.Fatalf("POST /login: body = %s, want redirect_to %q", body, tc.want)
			}
		})
	}
}

func TestOAuthStartCapturesAllowlistedRedirect(t *testing.T) {
	target := "http://127.0.0.1:8010/paper?tab=positions"
	h := newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.RedirectOrigins = []string{"http://127.0.0.1:8010"}
		cfg.Google = config.OAuthProviderConfig{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURI:  "http://127.0.0.1:7777/auth/google/callback",
		}
	})

	res, _ := browserGet(t, h.client(),
		h.srv.URL+"/auth/google?redirect_to="+url.QueryEscape(target))
	if res.StatusCode != http.StatusFound {
		t.Fatalf("GET /auth/google: status = %d, want 302", res.StatusCode)
	}
	for _, ck := range res.Cookies() {
		if ck.Name == cookiePostLogin {
			if ck.Value != target {
				t.Fatalf("post-login cookie = %q, want %q", ck.Value, target)
			}
			return
		}
	}
	t.Fatal("OAuth start did not set post-login redirect cookie")
}
