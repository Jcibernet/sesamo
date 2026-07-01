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
