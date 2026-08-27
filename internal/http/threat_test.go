package http

import (
	"context"
	"encoding/json"
	"fmt"
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
	resetRateLimits(t, pool)
	cfg := &config.Config{
		BaseURL:                 "http://127.0.0.1",
		CookieName:              "sid",
		CookieSecure:            false,
		SessionLifetime:         30 * 24 * time.Hour,
		SessionMaxLifetime:      90 * 24 * time.Hour,
		RollingRenewalThreshold: 15 * time.Minute,
		ServiceToken:            "svc-token-test",
		AdminAPIKey:             "admin-key-test",
		EmailProvider:           "log",
		EmailFrom:               "auth@test.local",
	}
	if mutate != nil {
		mutate(cfg)
	}
	h, err := NewServer(cfg, pool, testLogger())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
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
	c := h.client()
	form := url.Values{"email": {email}, "password": {password}}
	h.withCSRF(c, form)
	res, err := c.PostForm(h.srv.URL+"/signup", form)
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

// withCSRF completes the double-submit handshake for the client's cookie
// jar: it GETs /login in JSON mode (which sets the sesamo_csrf cookie)
// and adds the returned token to the form. Callers that need to test
// broken CSRF hand a form that already carries a csrf_token key — this
// helper leaves existing values alone.
func (h *harness) withCSRF(c *http.Client, form url.Values) {
	h.t.Helper()
	if form.Has("csrf_token") {
		return
	}
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/login?mode=json", nil)
	req.Header.Set("Accept", "application/json")
	res, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var payload struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		h.t.Fatalf("csrf bootstrap: %v", err)
	}
	if payload.CSRFToken == "" {
		h.t.Fatal("csrf bootstrap: empty csrf_token")
	}
	form.Set("csrf_token", payload.CSRFToken)
}

// postJSON posts form values, asking for JSON responses (headless).
func (h *harness) postJSON(c *http.Client, path string, form url.Values) (*http.Response, string) {
	h.withCSRF(c, form)
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
	if got := safeInternalPath(`/\evil.com`); got != "/" {
		t.Fatalf("backslash escape must be neutralized, got %q", got)
	}
	// The allowlisted-origin variant is covered exhaustively by
	// TestSafeRedirectTarget; here we pin that an empty allowlist keeps
	// the historical internal-only behavior for absolute URLs.
	if got := safeRedirectTarget(nil, "https://evil.com/x"); got != "/" {
		t.Fatalf("absolute URL without allowlist must be neutralized, got %q", got)
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

// ── Threat vector 17: spoofed X-Forwarded-For does not bypass the
// per-IP login rate limit (TrustProxy defaults false) ─────────────────
func TestThreat17_XFFSpoofDoesNotBypassIPRateLimit(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	var emails []string
	t.Cleanup(func() {
		if len(emails) == 0 {
			return
		}
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM audit_log WHERE detail->>'email' = ANY($1)`, emails)
	})
	var got429 bool
	for i := range 30 {
		email := uniqueEmail(fmt.Sprintf("xff%d", i))
		emails = append(emails, email)
		form := url.Values{"email": {email}, "password": {"whatever-bad"}}
		// A valid CSRF token: the point of this vector is the IP rate
		// limiter, not CSRF. CSRF rejection would mask the bucket test —
		// a token-less cross-site flood never reaches checkLoginRate —
		// so this models the realistic abuser: a headless client that
		// completed the handshake and now rotates XFF per request.
		h.withCSRF(c, form)
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/login",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		// Spoofed, per-request X-Forwarded-For: if this were honored, each
		// request would mint a fresh per-IP bucket and 429 would never fire.
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i))
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("expected the shared RemoteAddr bucket to trip 429 despite a fresh spoofed XFF per request")
	}
}

// ── Threat vector 18: security-relevant events are written to the
// audit trail (STRIDE: repudiation) ───────────────────────────────────
func TestThreat18_AuditTrailWritten(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("audit")
	password := "correct-horse-99"
	h.signup(email, password)

	var userID string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM audit_log WHERE actor_user = $1 OR detail->>'email' = $2`, userID, email)
	})

	c := h.client()
	h.postJSON(c, "/login", url.Values{"email": {email}, "password": {password}})
	h.postJSON(c, "/login", url.Values{"email": {email}, "password": {"wrong-password"}})
	h.postJSON(c, "/logout", url.Values{})

	var n int
	if err := h.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log
		 WHERE event = 'login.success' AND actor_user = $1 AND detail->>'method' = 'password'`,
		userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("expected a login.success audit row with actor_user set and detail.method=password")
	}

	if err := h.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log
		 WHERE event = 'login.failed' AND detail->>'email' = $1`,
		email).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("expected a login.failed audit row for the wrong-password attempt")
	}

	if err := h.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log
		 WHERE event = 'logout' AND actor_user = $1`,
		userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("expected a logout audit row with actor_user set to the user id")
	}
}

// ── Threat vector 19: oversized request bodies are rejected before
// handler logic runs (STRIDE: denial of service) ───────────────────────
func TestThreat19_OversizedBodyRejected(t *testing.T) {
	h := newHarness(t)
	c := h.client()

	padding := strings.Repeat("a", 128<<10) // 128 KiB, well past the 64 KiB cap
	form := url.Values{
		"email":    {uniqueEmail("oversized")},
		"password": {"whatever-12345"},
		"padding":  {padding},
	}
	res, _ := h.postJSON(c, "/login", form)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for an oversized body, got %d", res.StatusCode)
	}
	if h.sidCookie(c) != "" {
		t.Fatal("an oversized body must never result in a session cookie")
	}
}

// newStrictHarness is a local variant of newHarness with AuditStrict
// enabled (SESAMO_AUDIT_STRICT=true), used to verify that strict mode
// does not alter behavior when the database is healthy — it must only
// bite on write failure, never on the happy path.
func newStrictHarness(t *testing.T) *harness {
	return newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.AuditStrict = true
	})
}

// ── Strict audit mode: a healthy database must not change behavior on
// the happy path (SESAMO_AUDIT_STRICT only bites when the write fails,
// see internal/audit for the failure-injection unit tests) ───────────
func TestThreat20_StrictAuditHealthyLoginUnaffected(t *testing.T) {
	h := newStrictHarness(t)
	email := uniqueEmail("strict-audit")
	password := "correct-horse-99"
	h.signup(email, password)

	var userID string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM audit_log WHERE actor_user = $1`, userID)
	})

	c := h.client()
	res, body := h.postJSON(c, "/login", url.Values{"email": {email}, "password": {password}})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on login with strict audit + healthy DB, got %d: %s", res.StatusCode, body)
	}
	if h.sidCookie(c) == "" {
		t.Fatal("expected sid cookie to be set after a successful strict-mode login")
	}

	var n int
	if err := h.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log
		 WHERE event = 'login.success' AND actor_user = $1 AND detail->>'method' = 'password'`,
		userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("expected a login.success audit row even in strict mode against a healthy DB")
	}
}

// adminPost posts to an admin endpoint with the test admin key.
func (h *harness) adminPost(path string, form url.Values) (*http.Response, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer admin-key-test")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(body)
}

// setUserDisabled flips the disabled column directly, for test setup.
func setUserDisabled(t *testing.T, pool *pgxpool.Pool, userID string, disabled bool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET disabled = $2 WHERE id = $1`, userID, disabled); err != nil {
		t.Fatal(err)
	}
}

// ── Threat vector 21: a cross-site form POST without the CSRF pair is
// rejected before any credential logic runs (login CSRF) ──────────────
func TestThreat21_CrossSitePostWithoutTokenRejected(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("csrf-blast")
	h.signup(email, "correct-horse-csrf")

	c := h.client()
	// The attacker's form carries credentials but no token and (here) no
	// sesamo_csrf cookie: exactly what a forged cross-site POST has.
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/login",
		strings.NewReader(url.Values{"email": {email}, "password": {"correct-horse-csrf"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("tokenless login POST must be 403, got %d (%s)", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "csrf_failed") {
		t.Fatalf("expected csrf_failed code, got: %s", body)
	}
	if h.sidCookie(c) != "" {
		t.Fatal("a CSRF-rejected login must never mint a session cookie")
	}
}

// ── Threat vector 22: a headless client that completed the handshake
// (cookie + token from GET /login JSON) logs in successfully ──────────
func TestThreat22_CsrfValidPairAccepted(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("csrf-good")
	password := "correct-horse-csrf2"
	h.signup(email, password)

	c := h.client()
	form := url.Values{"email": {email}, "password": {password}}
	h.withCSRF(c, form)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("valid CSRF pair must log in: got %d (%s)", res.StatusCode, body)
	}
	if h.sidCookie(c) == "" {
		t.Fatal("expected session cookie after a valid CSRF pair")
	}
}

// ── Threat vector 23: cookie and token halves that do not match are
// rejected even when both are present ─────────────────────────────────
func TestThreat23_CsrfMismatchRejected(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("csrf-bad")
	h.signup(email, "correct-horse-csrf3")

	c := h.client()
	// Bootstrap the cookie, then send a DIFFERENT token in the form.
	form := url.Values{
		"email": {email}, "password": {"correct-horse-csrf3"},
		"csrf_token": {"totally-unrelated-token-value"},
	}
	h.withCSRF(c, form)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("mismatched CSRF pair must be 403, got %d (%s)", res.StatusCode, body)
	}
	if h.sidCookie(c) != "" {
		t.Fatal("a CSRF-mismatched login must never mint a session cookie")
	}
}

// ── Threat vector 24: the account kill switch — introspection goes
// inactive, password login is indistinguishable from bad credentials,
// the magic link is refused, and re-enable restores access ────────────
func TestThreat24_DisabledUserKillSwitch(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("killswitch")
	password := "correct-horse-kill"
	h.signup(email, password)

	var userID string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(), `DELETE FROM audit_log WHERE actor_user = $1`, userID)
	})

	// Live session exists, then the operator pulls the switch.
	c := h.client()
	h.postJSON(c, "/login", url.Values{"email": {email}, "password": {password}})
	sid := h.sidCookie(c)
	if sid == "" {
		t.Fatal("expected a live session before disable")
	}
	if res, body := h.adminPost("/v1/admin/users/"+userID+"/disable",
		url.Values{"disabled": {"true"}}); res.StatusCode != http.StatusOK {
		t.Fatalf("admin disable failed: %d (%s)", res.StatusCode, body)
	}

	// Existing session: introspect inactive (and the row is gone).
	if _, b := h.introspect(sid); !strings.Contains(b, `"active":false`) {
		t.Fatalf("disabled user's session must introspect inactive: %s", b)
	}

	// New password login: byte-identical to wrong-password (no oracle).
	cWrong := h.client()
	_, disabledBody := h.postJSON(cWrong, "/login", url.Values{"email": {email}, "password": {password}})
	_, badPassBody := h.postJSON(h.client(), "/login", url.Values{"email": {email}, "password": {"wrong-password"}})
	if disabledBody != badPassBody {
		t.Fatalf("disabled login must look like bad credentials: %q vs %q", disabledBody, badPassBody)
	}

	// Magic link: refused with the generic invalid-link answer, and no
	// session is minted.
	tok, err := issueRawMagicLinkToken(h.pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	res, _ := browserGet(t, h.client(), h.srv.URL+"/magiclink/confirm?token="+tok)
	if res.StatusCode == http.StatusFound {
		t.Fatal("disabled user's magic link must not mint a session")
	}

	// Re-enable restores logins.
	if res, body := h.adminPost("/v1/admin/users/"+userID+"/disable",
		url.Values{"disabled": {"false"}}); res.StatusCode != http.StatusOK {
		t.Fatalf("admin enable failed: %d (%s)", res.StatusCode, body)
	}
	cBack := h.client()
	if res, body := h.postJSON(cBack, "/login", url.Values{"email": {email}, "password": {password}}); res.StatusCode != http.StatusOK {
		t.Fatalf("re-enabled user must log in: %d (%s)", res.StatusCode, body)
	}

	// The kill switch is evidenced in the audit trail.
	var n int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE event = 'user.disabled' AND actor_user = $1`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("expected a user.disabled audit row")
	}
}
