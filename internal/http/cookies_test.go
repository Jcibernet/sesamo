package http

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/jcibernet/sesamo/internal/config"
)

func newHarnessWithDomain(t *testing.T, cookieDomain string) *harness {
	t.Helper()
	dsn := os.Getenv("SESAMO_TEST_DB")
	if dsn == "" {
		t.Skip("SESAMO_TEST_DB not set; skipping integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	cfg := &config.Config{
		BaseURL:                 "http://127.0.0.1",
		CookieName:              "sid",
		CookieSecure:            false,
		CookieDomain:            cookieDomain,
		SessionLifetime:         30 * 24 * time.Hour,
		RollingRenewalThreshold: 15 * time.Minute,
		ServiceToken:            "svc-token-test",
		AdminAPIKey:             "admin-key-test",
		EmailProvider:           "log",
		EmailFrom:               "auth@test.local",
	}
	h := NewServer(cfg, pool, testLogger())
	srv := httptest.NewServer(h)
	t.Cleanup(func() { srv.Close(); pool.Close() })
	return &harness{srv: srv, pool: pool, t: t}
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
