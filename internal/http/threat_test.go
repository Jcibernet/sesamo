package http

import (
	"context"
	"io"
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
	"github.com/jcibernet/sesamo/internal/crypto"
)

// harness boots the real handler against the dev DB via httptest. Tests
// that need a DB skip cleanly when SESAMO_TEST_DB is unset.
type harness struct {
	srv  *httptest.Server
	pool *pgxpool.Pool
	t    *testing.T
}

func newHarness(t *testing.T) *harness {
	return newHarnessWithConfig(t, nil)
}

// newHarnessWithConfig boots the real handler against the dev DB, applying
// an optional mutation to the base test config before building the server.
func newHarnessWithConfig(t *testing.T, mutate func(*config.Config)) *harness {
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
		SessionLifetime:         30 * 24 * time.Hour,
		RollingRenewalThreshold: 15 * time.Minute,
		ServiceToken:            "svc-token-test",
		AdminAPIKey:             "admin-key-test",
		EmailProvider:           "log",
		EmailFrom:               "auth@test.local",
	}
	if mutate != nil {
		mutate(cfg)
	}
	h := NewServer(cfg, pool, testLogger())
	srv := httptest.NewServer(h)
	t.Cleanup(func() { srv.Close(); pool.Close() })
	return &harness{srv: srv, pool: pool, t: t}
}

func (h *harness) client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // do not follow redirects
		},
	}
}

func (h *harness) signup(email, password string) {
	h.t.Helper()
	res, err := http.PostForm(h.srv.URL+"/signup", url.Values{
		"email": {email}, "password": {password},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	res.Body.Close()
	h.t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(), `DELETE FROM users WHERE email = $1`, email)
	})
}

func uniqueEmail(prefix string) string {
	return prefix + "-" + crypto.GenerateToken()[:10] + "@test.local"
}

// postJSON posts form values, asking for JSON responses (headless).
func (h *harness) postJSON(c *http.Client, path string, form url.Values) (*http.Response, string) {
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(body)
}

func (h *harness) introspect(token string) (*http.Response, string) {
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/introspect",
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer svc-token-test")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(body)
}

func (h *harness) sidCookie(c *http.Client) string {
	u, _ := url.Parse(h.srv.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == "sid" {
			return ck.Value
		}
	}
	return ""
}

// ── Threat vector 1: unauthenticated introspection is denied ──────────
func TestThreat01_IntrospectRequiresServiceToken(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/introspect", nil)
	res, _ := http.DefaultClient.Do(req)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", res.StatusCode)
	}
}

// ── Threat vector 2: wrong service token is rejected (constant-time) ──
func TestThreat02_IntrospectWrongServiceToken(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/introspect", nil)
	req.Header.Set("Authorization", "Bearer not-the-token")
	res, _ := http.DefaultClient.Do(req)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", res.StatusCode)
	}
}

// ── Threat vector 3: forged/random session token is inactive ─────────
func TestThreat03_ForgedSessionTokenInactive(t *testing.T) {
	h := newHarness(t)
	_, body := h.introspect("totally-made-up-token")
	if !strings.Contains(body, `"active":false`) {
		t.Fatalf("forged token should be inactive: %s", body)
	}
}

// ── Threat vector 4: user enumeration — login error is identical for
// nonexistent user vs wrong password ─────────────────────────────────
func TestThreat04_NoUserEnumerationOnLogin(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("enum")
	h.signup(email, "correct-horse-1")

	c := h.client()
	_, wrongPass := h.postJSON(c, "/login", url.Values{"email": {email}, "password": {"wrong-pass-9"}})
	_, noUser := h.postJSON(c, "/login", url.Values{"email": {uniqueEmail("ghost")}, "password": {"wrong-pass-9"}})
	if wrongPass != noUser {
		t.Fatalf("enumeration leak: %q != %q", wrongPass, noUser)
	}
}

// ── Threat vector 5: password reset request does not reveal existence ─
func TestThreat05_NoEnumerationOnResetRequest(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("reset")
	h.signup(email, "correct-horse-2")

	c := h.client()
	res1, body1 := h.postJSON(c, "/reset", url.Values{"email": {email}})
	c2 := h.client()
	res2, body2 := h.postJSON(c2, "/reset", url.Values{"email": {uniqueEmail("ghost")}})
	if res1.StatusCode != 200 || res2.StatusCode != 200 || body1 != body2 {
		t.Fatalf("reset enumeration leak: %d/%s vs %d/%s", res1.StatusCode, body1, res2.StatusCode, body2)
	}
}

// ── Threat vector 6: signup on an existing email does not leak ───────
func TestThreat06_NoEnumerationOnSignup(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("dup")
	h.signup(email, "correct-horse-3")

	c := h.client()
	res, body := h.postJSON(c, "/signup", url.Values{"email": {email}, "password": {"another-pass-4"}})
	if res.StatusCode != 200 || !strings.Contains(body, "verification_sent") {
		t.Fatalf("signup on existing email should look identical: %d %s", res.StatusCode, body)
	}
}

// ── Threat vector 7: session is revoked on logout ────────────────────
func TestThreat07_SessionRevokedOnLogout(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("logout")
	h.signup(email, "correct-horse-5")

	c := h.client()
	h.postJSON(c, "/login", url.Values{"email": {email}, "password": {"correct-horse-5"}})
	sid := h.sidCookie(c)
	if sid == "" {
		t.Fatal("expected session cookie")
	}
	if _, b := h.introspect(sid); !strings.Contains(b, `"active":true`) {
		t.Fatalf("session should be active before logout: %s", b)
	}
	h.postJSON(c, "/logout", url.Values{})
	if _, b := h.introspect(sid); !strings.Contains(b, `"active":false`) {
		t.Fatalf("session must be inactive after logout: %s", b)
	}
}

// ── Threat vector 8: password reset revokes all existing sessions ────
func TestThreat08_ResetRevokesAllSessions(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("resetrev")
	h.signup(email, "correct-horse-6")

	c := h.client()
	h.postJSON(c, "/login", url.Values{"email": {email}, "password": {"correct-horse-6"}})
	sid := h.sidCookie(c)

	// Look up the user id and issue a reset token directly via DB+store
	// path by calling /reset then reading the token from one_time_tokens.
	var userID string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	tok, err := issueRawResetToken(h.pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	res, _ := h.postJSON(h.client(), "/reset/confirm", url.Values{
		"token": {tok}, "password": {"brand-new-pass-7"},
	})
	if res.StatusCode != 200 {
		t.Fatalf("reset confirm failed: %d", res.StatusCode)
	}
	if _, b := h.introspect(sid); !strings.Contains(b, `"active":false`) {
		t.Fatalf("old session must die after password reset: %s", b)
	}
}

// ── Threat vector 9: OAuth callback rejects state mismatch (CSRF) ─────
func TestThreat09_OAuthStateMismatchRejected(t *testing.T) {
	// Register a real Google provider so the callback reaches the state
	// check instead of short-circuiting on "provider not found" (404).
	// The CSRF/state check runs before any network call to Google, so
	// dummy credentials are enough to exercise the security-relevant path.
	h := newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.Google = config.OAuthProviderConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURI:  "http://127.0.0.1/auth/google/callback",
		}
	})
	c := h.client()
	// No state cookie set; provider returns some state => must reject
	// with a specific state_mismatch (400), NOT a generic 404.
	req, _ := http.NewRequest(http.MethodGet,
		h.srv.URL+"/auth/google/callback?code=abc&state=attacker", nil)
	req.Header.Set("Accept", "application/json")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("state mismatch must return 400, got %d (%s)", res.StatusCode, body)
	}
	if !strings.Contains(string(body), codeStateMismatch) {
		t.Fatalf("expected %q error code, got body: %s", codeStateMismatch, body)
	}
}

// ── Threat vector 10: one-time token cannot be reused ────────────────
func TestThreat10_OneTimeTokenSingleUse(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("otp")
	h.signup(email, "correct-horse-8")
	var userID string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	tok, err := issueRawResetToken(h.pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	r1, _ := h.postJSON(h.client(), "/reset/confirm", url.Values{"token": {tok}, "password": {"new-pass-aaa-1"}})
	if r1.StatusCode != 200 {
		t.Fatalf("first use should succeed: %d", r1.StatusCode)
	}
	r2, _ := h.postJSON(h.client(), "/reset/confirm", url.Values{"token": {tok}, "password": {"new-pass-bbb-2"}})
	if r2.StatusCode == 200 {
		t.Fatal("token reuse must fail")
	}
}

// ── Threat vector 11: admin endpoints require the admin key ──────────
func TestThreat11_AdminRequiresKey(t *testing.T) {
	h := newHarness(t)
	res, err := http.Get(h.srv.URL + "/v1/admin/users/some-id")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin must require key: %d", res.StatusCode)
	}
}

// ── Threat vector 12: service token cannot access admin endpoints ────
func TestThreat12_ServiceTokenIsNotAdmin(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/v1/admin/users/some-id", nil)
	req.Header.Set("Authorization", "Bearer svc-token-test") // wrong key for admin
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("service token must not be accepted as admin: %d", res.StatusCode)
	}
}

// ── Threat vector 13: brute force is rate limited per identity ───────
func TestThreat13_LoginRateLimited(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("brute")
	h.signup(email, "correct-horse-9")
	c := h.client()
	var got429 bool
	for i := 0; i < 12; i++ {
		res, _ := h.postJSON(c, "/login", url.Values{"email": {email}, "password": {"bad"}})
		if res.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("expected rate limiting to kick in")
	}
}

// ── Threat vector 14: logout requires POST (no GET/CSRF logout) ──────
func TestThreat14_LogoutIsPostOnly(t *testing.T) {
	h := newHarness(t)
	res, err := http.Get(h.srv.URL + "/logout")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /logout must not be allowed: %d", res.StatusCode)
	}
}

// ── Threat vector 15: open-redirect protection on post-login target ──
func TestThreat15_OpenRedirectBlocked(t *testing.T) {
	if got := safeInternalPath("//evil.com"); got != "/" {
		t.Fatalf("protocol-relative URL must be neutralized, got %q", got)
	}
	if got := safeInternalPath("https://evil.com"); got != "/" {
		t.Fatalf("absolute URL must be neutralized, got %q", got)
	}
	if got := safeInternalPath("/dashboard"); got != "/dashboard" {
		t.Fatalf("safe internal path must pass, got %q", got)
	}
}

// ── Threat vector 16: security headers present on responses ──────────
func TestThreat16_SecurityHeadersPresent(t *testing.T) {
	h := newHarness(t)
	res, err := http.Get(h.srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	for _, hdr := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"} {
		if res.Header.Get(hdr) == "" {
			t.Fatalf("missing security header %s", hdr)
		}
	}
}
