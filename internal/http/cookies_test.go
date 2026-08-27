package http

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/jcibernet/sesamo/internal/config"
)

func newHarnessWithDomain(t *testing.T, cookieDomain string) *harness {
	return newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.CookieDomain = cookieDomain
	})
}

func TestCookieDomainAttr(t *testing.T) {
	t.Run("unset yields no Domain attribute", func(t *testing.T) {
		h := newHarnessWithDomain(t, "")
		email := uniqueEmail("cookiedomain")
		h.signup(email, "correct-horse-1")

		jar, _ := cookiejar.New(nil)
		c := &http.Client{
			Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/login",
			strings.NewReader(url.Values{"email": {email}, "password": {"correct-horse-1"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()

		for _, ck := range res.Cookies() {
			if ck.Name == "sid" {
				if ck.Domain != "" {
					t.Fatalf("expected no Domain attribute, got %q", ck.Domain)
				}
				return
			}
		}
		t.Fatal("sid cookie not found in Set-Cookie headers")
	})

	t.Run("set yields correct Domain attribute", func(t *testing.T) {
		h := newHarnessWithDomain(t, ".example.com")
		email := uniqueEmail("cookiedomain")
		h.signup(email, "correct-horse-2")

		jar, _ := cookiejar.New(nil)
		c := &http.Client{
			Jar: jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/login",
			strings.NewReader(url.Values{"email": {email}, "password": {"correct-horse-2"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()

		for _, ck := range res.Cookies() {
			if ck.Name == "sid" {
				if ck.Domain != "example.com" {
					t.Fatalf("expected Domain=example.com, got %q", ck.Domain)
				}
				return
			}
		}
		t.Fatal("sid cookie not found in Set-Cookie headers")
	})
}

// TestSessionCookieSecurityFlags asserts the actual security properties of
// the session cookie: HttpOnly (no JS access), SameSite=Lax (CSRF defense),
// and Secure when CookieSecure is enabled (production). Only the Domain
// attribute was covered before; a regression flipping any of these flags
// would previously go undetected.
func TestSessionCookieSecurityFlags(t *testing.T) {
	h := newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.CookieSecure = true // production posture
	})
	email := uniqueEmail("cookieflags")
	h.signup(email, "correct-horse-3")

	jar, _ := cookiejar.New(nil)
	c := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/login",
		strings.NewReader(url.Values{"email": {email}, "password": {"correct-horse-3"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	for _, ck := range res.Cookies() {
		if ck.Name != "sid" {
			continue
		}
		if !ck.HttpOnly {
			t.Error("session cookie must be HttpOnly")
		}
		if !ck.Secure {
			t.Error("session cookie must be Secure when CookieSecure=true")
		}
		if ck.SameSite != http.SameSiteLaxMode {
			t.Errorf("session cookie SameSite=%d, want Lax(%d)", ck.SameSite, http.SameSiteLaxMode)
		}
		return
	}
	t.Fatal("sid cookie not found in Set-Cookie headers")
}

// TestSafeRedirectTarget pins the whole trust boundary of post-login and
// post-logout redirects: internal paths pass, allowlisted origins pass
// with path+query preserved and fragment dropped, and every escape
// vector collapses to "/". Pure function — no DB required.
func TestSafeRedirectTarget(t *testing.T) {
	origins := []string{"http://127.0.0.1:8010", "https://app.example.com"}

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty falls back to root", raw: "", want: "/"},
		{name: "internal path passes", raw: "/paper?x=1", want: "/paper?x=1"},
		{name: "protocol-relative collapses", raw: "//evil.com/paper", want: "/"},
		{name: "backslash trick collapses", raw: `/\evil.com`, want: "/"},
		{
			name: "allowlisted origin keeps path and query",
			raw:  "http://127.0.0.1:8010/paper?x=1",
			want: "http://127.0.0.1:8010/paper?x=1",
		},
		{
			name: "fragment is dropped from an allowlisted target",
			raw:  "https://app.example.com/dash#token=abc",
			want: "https://app.example.com/dash",
		},
		{
			name: "bare allowlisted origin lands on its root",
			raw:  "https://app.example.com",
			want: "https://app.example.com/",
		},
		{name: "unlisted origin collapses", raw: "https://evil.com/paper", want: "/"},
		{name: "scheme mismatch collapses", raw: "http://app.example.com/dash", want: "/"},
		{name: "port mismatch collapses", raw: "http://127.0.0.1:9999/paper", want: "/"},
		{name: "lookalike host collapses", raw: "https://app.example.com.evil.com/x", want: "/"},
		{name: "userinfo collapses", raw: "https://app.example.com@evil.com/x", want: "/"},
		{name: "javascript scheme collapses", raw: "javascript:alert(1)", want: "/"},
		{
			name: "host case-insensitivity matches the allowlist",
			raw:  "https://APP.EXAMPLE.COM/dash?x=1",
			want: "https://app.example.com/dash?x=1",
		},
		{name: "tab-smuggled protocol-relative collapses", raw: "/\t/evil.com", want: "/"},
		{name: "newline-smuggled target collapses", raw: "https://app.example.com/\n.evil.com", want: "/"},
		{name: "carriage-return target collapses", raw: "/dash\r", want: "/"},
		{name: "garbage collapses", raw: "::not a url::", want: "/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeRedirectTarget(origins, tc.raw); got != tc.want {
				t.Errorf("safeRedirectTarget(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}

	t.Run("empty allowlist keeps internal-only behavior", func(t *testing.T) {
		if got := safeRedirectTarget(nil, "http://127.0.0.1:8010/paper"); got != "/" {
			t.Errorf("absolute target without allowlist = %q, want %q", got, "/")
		}
		if got := safeRedirectTarget(nil, "/paper"); got != "/paper" {
			t.Errorf("internal target without allowlist = %q, want %q", got, "/paper")
		}
	})
}
