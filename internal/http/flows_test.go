package http

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jcibernet/sesamo/internal/config"
)

// This file exercises the browser (HTML) flow that content-negotiates
// alongside the existing JSON API: GET pages render forms, POST/GET
// outcomes render message.html, and the two modes must never diverge in
// status or fields — only in representation. See threat_test.go for the
// harness (newHarness, signup, postJSON) and helper_test.go for
// issueRawResetToken.

// browserGet issues a GET with no Accept header, emulating a real
// browser navigation (as opposed to a headless JSON client).
func browserGet(t *testing.T, c *http.Client, rawURL string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(body)
}

// browserPostForm posts form-encoded values with no Accept header,
// emulating a real <form method="POST"> submission.
func browserPostForm(t *testing.T, c *http.Client, rawURL string, form url.Values) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(body)
}

// jsonGet issues a GET asking for JSON (headless), mirroring postJSON's
// content negotiation but for GET-only pages.
func jsonGet(t *testing.T, c *http.Client, rawURL string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(body)
}

// ── Flow 1: GET /reset renders the email form for browsers and the
// field descriptor for headless (JSON) clients ────────────────────────
func TestFlow01_ResetPageFormAndJSON(t *testing.T) {
	h := newHarness(t)
	c := h.client()

	res, body := browserGet(t, c, h.srv.URL+"/reset")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /reset: expected 200, got %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("GET /reset: expected text/html, got %q", ct)
	}
	if !strings.Contains(body, `action="http://127.0.0.1/reset"`) {
		t.Fatalf("GET /reset: missing form action pointing at /reset, body: %s", body)
	}
	if !strings.Contains(body, `name="email"`) {
		t.Fatalf("GET /reset: missing email input, body: %s", body)
	}

	jres, jbody := jsonGet(t, c, h.srv.URL+"/reset")
	if jres.StatusCode != http.StatusOK {
		t.Fatalf("GET /reset (json): expected 200, got %d", jres.StatusCode)
	}
	if !strings.Contains(jbody, `"method":"POST"`) || !strings.Contains(jbody, `"fields":["email"]`) {
		t.Fatalf("GET /reset (json): unexpected fields descriptor, body: %s", jbody)
	}
}

// ── Flow 2: GET /reset/confirm embeds the token in the rendered form
// WITHOUT consuming it — the one-time token must still work afterwards
// on the real POST. This is the render-must-not-consume invariant,
// exercised end to end through a real signup + minted token ───────────
func TestFlow02_ResetConfirmPageDoesNotConsumeToken(t *testing.T) {
	h := newHarness(t)
	emailAddr := uniqueEmail("flowreset")
	h.signup(emailAddr, "correct-horse-flow2")

	var userID string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE email = $1`, emailAddr).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(),
			`DELETE FROM audit_log WHERE actor_user = $1`, userID)
	})

	tok, err := issueRawResetToken(h.pool, userID)
	if err != nil {
		t.Fatal(err)
	}

	c := h.client()
	res, body := browserGet(t, c, h.srv.URL+"/reset/confirm?token="+tok)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /reset/confirm: expected 200, got %d", res.StatusCode)
	}
	if !strings.Contains(body, `value="`+tok+`"`) {
		t.Fatalf("GET /reset/confirm: token not embedded in form, body: %s", body)
	}

	// The GET above must not have burned the single use: the POST below,
	// reusing the very same token, must still succeed.
	pres, pbody := browserPostForm(t, c, h.srv.URL+"/reset/confirm", url.Values{
		"token": {tok}, "password": {"brand-new-flow-pass-2"},
	})
	if pres.StatusCode != http.StatusOK {
		t.Fatalf("POST /reset/confirm: expected 200, got %d: %s", pres.StatusCode, pbody)
	}
	if !strings.Contains(pbody, "Contraseña actualizada") {
		t.Fatalf("POST /reset/confirm: missing success message, body: %s", pbody)
	}
}

// ── Flow 3: an invalid reset token is rejected as HTML for browsers and
// as a structured invalid_request error for JSON clients ──────────────
func TestFlow03_ResetConfirmInvalidTokenBrowserAndJSON(t *testing.T) {
	h := newHarness(t)

	c := h.client()
	res, body := browserPostForm(t, c, h.srv.URL+"/reset/confirm", url.Values{
		"token": {"garbage-token-does-not-exist"}, "password": {"whatever-valid-pass"},
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("browser POST /reset/confirm garbage token: expected 400, got %d", res.StatusCode)
	}
	if !strings.Contains(body, "Enlace inválido") {
		t.Fatalf("browser POST /reset/confirm garbage token: expected HTML error message, body: %s", body)
	}

	jres, jbody := h.postJSON(h.client(), "/reset/confirm", url.Values{
		"token": {"garbage-token-does-not-exist"}, "password": {"whatever-valid-pass"},
	})
	if jres.StatusCode != http.StatusBadRequest {
		t.Fatalf("json POST /reset/confirm garbage token: expected 400, got %d", jres.StatusCode)
	}
	if !strings.Contains(jbody, `"code":"invalid_request"`) {
		t.Fatalf("json POST /reset/confirm garbage token: expected invalid_request code, body: %s", jbody)
	}
}

// ── Flow 4: an invalid verification token is rejected as HTML for
// browsers and as JSON for headless clients ────────────────────────────
func TestFlow04_VerifyInvalidTokenBrowserAndJSON(t *testing.T) {
	h := newHarness(t)
	c := h.client()

	res, body := browserGet(t, c, h.srv.URL+"/verify?token=garbage-token-does-not-exist")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("browser GET /verify garbage token: expected 400, got %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("browser GET /verify garbage token: expected text/html, got %q", ct)
	}
	if !strings.Contains(body, "Enlace inválido") {
		t.Fatalf("browser GET /verify garbage token: expected HTML error message, body: %s", body)
	}

	jres, jbody := jsonGet(t, c, h.srv.URL+"/verify?token=garbage-token-does-not-exist")
	if jres.StatusCode != http.StatusBadRequest {
		t.Fatalf("json GET /verify garbage token: expected 400, got %d", jres.StatusCode)
	}
	if !strings.Contains(jbody, `"code":"invalid_request"`) {
		t.Fatalf("json GET /verify garbage token: expected invalid_request code, body: %s", jbody)
	}
}

// ── Flow 5: a browser posting /magiclink with no email is bounced back
// to the login form with an error banner instead of raw JSON ──────────
func TestFlow05_MagicLinkEmptyEmailBrowserRedirect(t *testing.T) {
	h := newHarness(t)
	c := h.client() // CheckRedirect: ErrUseLastResponse — do not follow

	res, _ := browserPostForm(t, c, h.srv.URL+"/magiclink", url.Values{"email": {""}})
	if res.StatusCode != http.StatusFound {
		t.Fatalf("browser POST /magiclink empty email: expected 302, got %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/login?error=email_required" {
		t.Fatalf("browser POST /magiclink empty email: expected redirect to /login?error=email_required, got %q", loc)
	}
}

// ── Flow 6: the login page wires the magic-link button through the
// password form (formaction/formnovalidate) and carries no leftover
// hidden email field or inline style attributes (CSP compliance) ──────
func TestFlow06_LoginPageMagicLinkWiringAndCSP(t *testing.T) {
	h := newHarness(t)
	c := h.client()

	res, body := browserGet(t, c, h.srv.URL+"/login")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /login: expected 200, got %d", res.StatusCode)
	}
	if !strings.Contains(body, `formaction="http://127.0.0.1/magiclink"`) {
		t.Fatalf("GET /login: expected magic-link formaction on the password form, body: %s", body)
	}
	if !strings.Contains(body, "formnovalidate") {
		t.Fatalf("GET /login: expected formnovalidate on the magic-link submit button, body: %s", body)
	}
	if strings.Contains(body, `name="email" value=""`) {
		t.Fatalf("GET /login: leftover hidden email input must be gone, body: %s", body)
	}
	if strings.Contains(body, `style="`) {
		t.Fatalf("GET /login: inline style attribute violates CSP, body: %s", body)
	}
}

// newRedirectHarness boots the server with a consuming app allowlisted,
// mirroring the Marketmaker deployment (SPA on another local origin).
func newRedirectHarness(t *testing.T) *harness {
	return newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.RedirectOrigins = []string{"http://127.0.0.1:8010"}
	})
}

// ── Flow 6: password login round-trips to the consuming app. GET /login
// captures redirect_to; the form POST lands the browser back on the
// exact allowlisted path+query it came from ───────────────────────────
func TestFlow07_PasswordLoginRoundTripsRedirect(t *testing.T) {
	h := newRedirectHarness(t)
	emailAddr := uniqueEmail("flowredirect")
	h.signup(emailAddr, "correct-horse-flow6")
	c := h.client()

	target := "http://127.0.0.1:8010/paper?x=1"
	res, _ := browserGet(t, c, h.srv.URL+"/login?redirect_to="+url.QueryEscape(target))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /login: expected 200, got %d", res.StatusCode)
	}

	pres, _ := browserPostForm(t, c, h.srv.URL+"/login", url.Values{
		"email": {emailAddr}, "password": {"correct-horse-flow6"},
	})
	if pres.StatusCode != http.StatusFound {
		t.Fatalf("POST /login: expected 302, got %d", pres.StatusCode)
	}
	if loc := pres.Header.Get("Location"); loc != target {
		t.Fatalf("POST /login: expected redirect to %q, got %q", target, loc)
	}
	// The one-shot destination must not survive the login that used it.
	for _, ck := range pres.Cookies() {
		if ck.Name == cookiePostLogin && ck.MaxAge >= 0 {
			t.Fatalf("post-login cookie must be cleared after use, got MaxAge=%d", ck.MaxAge)
		}
	}
}

// ── Flow 7: a login without any captured destination keeps the
// pre-existing behavior and lands on "/" ──────────────────────────────
func TestFlow08_PasswordLoginWithoutRedirectLandsOnRoot(t *testing.T) {
	h := newRedirectHarness(t)
	emailAddr := uniqueEmail("flownoredirect")
	h.signup(emailAddr, "correct-horse-flow7")
	c := h.client()

	pres, _ := browserPostForm(t, c, h.srv.URL+"/login", url.Values{
		"email": {emailAddr}, "password": {"correct-horse-flow7"},
	})
	if pres.StatusCode != http.StatusFound {
		t.Fatalf("POST /login: expected 302, got %d", pres.StatusCode)
	}
	if loc := pres.Header.Get("Location"); loc != "/" {
		t.Fatalf("POST /login: expected redirect to /, got %q", loc)
	}
}

// ── Flow 8: a hostile redirect_to (unlisted origin, protocol-relative)
// is neutralized at capture time and the login lands on "/" ───────────
func TestFlow09_HostileRedirectTargetsCollapse(t *testing.T) {
	h := newRedirectHarness(t)
	emailAddr := uniqueEmail("flowhostile")
	h.signup(emailAddr, "correct-horse-flow8")

	for _, hostile := range []string{
		"https://evil.com/phish",
		"//evil.com/phish",
		"http://127.0.0.1:9999/paper",
		"http://127.0.0.1:8010@evil.com/",
	} {
		c := h.client()
		browserGet(t, c, h.srv.URL+"/login?redirect_to="+url.QueryEscape(hostile))
		pres, _ := browserPostForm(t, c, h.srv.URL+"/login", url.Values{
			"email": {emailAddr}, "password": {"correct-horse-flow8"},
		})
		if pres.StatusCode != http.StatusFound {
			t.Fatalf("POST /login (%q): expected 302, got %d", hostile, pres.StatusCode)
		}
		if loc := pres.Header.Get("Location"); loc != "/" {
			t.Fatalf("POST /login (%q): expected redirect to /, got %q", hostile, loc)
		}
	}
}

// ── Flow 9: the magic-link confirm inherits the destination captured at
// GET /login — the emailed link itself never carries a redirect ───────
func TestFlow10_MagicLinkPreservesRedirect(t *testing.T) {
	h := newRedirectHarness(t)
	emailAddr := uniqueEmail("flowmagic")
	h.signup(emailAddr, "correct-horse-flow9")

	var userID string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE email = $1`, emailAddr).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	tok, err := issueRawMagicLinkToken(h.pool, userID)
	if err != nil {
		t.Fatal(err)
	}

	target := "http://127.0.0.1:8010/paper"
	c := h.client()
	browserGet(t, c, h.srv.URL+"/login?redirect_to="+url.QueryEscape(target))

	res, _ := browserGet(t, c, h.srv.URL+"/magiclink/confirm?token="+tok)
	if res.StatusCode != http.StatusFound {
		t.Fatalf("GET /magiclink/confirm: expected 302, got %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != target {
		t.Fatalf("GET /magiclink/confirm: expected redirect to %q, got %q", target, loc)
	}
}

// ── Flow 10: logout accepts an allowlisted redirect_to and rejects an
// unlisted one, so a consuming app can land its own signed-out page ───
func TestFlow11_LogoutRedirectsToAllowlistedTarget(t *testing.T) {
	h := newRedirectHarness(t)
	emailAddr := uniqueEmail("flowlogout")
	h.signup(emailAddr, "correct-horse-flow10")
	c := h.client()

	browserPostForm(t, c, h.srv.URL+"/login", url.Values{
		"email": {emailAddr}, "password": {"correct-horse-flow10"},
	})

	target := "http://127.0.0.1:8010/signed-out"
	res, _ := browserPostForm(t, c, h.srv.URL+"/logout", url.Values{"redirect_to": {target}})
	if res.StatusCode != http.StatusFound {
		t.Fatalf("POST /logout: expected 302, got %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != target {
		t.Fatalf("POST /logout: expected redirect to %q, got %q", target, loc)
	}

	res2, _ := browserPostForm(t, c, h.srv.URL+"/logout", url.Values{"redirect_to": {"https://evil.com/"}})
	if loc := res2.Header.Get("Location"); loc != "/" {
		t.Fatalf("POST /logout hostile: expected redirect to /, got %q", loc)
	}
}

// ── Flow 12: SESAMO_SIGNUP=disabled refuses new accounts with one
// stable response while existing users keep logging in ────────────────
func TestFlow12_SignupDisabled(t *testing.T) {
	// The existing account is created while signup is still public…
	h := newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.Signup = config.SignupDisabled
		cfg.RedirectOrigins = []string{"http://127.0.0.1:8010"}
	})
	emailAddr := uniqueEmail("flowsignupoff")
	var userID string
	if err := h.pool.QueryRow(context.Background(),
		`INSERT INTO users (id, email, email_verified) VALUES (gen_random_uuid(), $1, true) RETURNING id`,
		emailAddr).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = h.pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})

	c := h.client()
	newEmail := uniqueEmail("flowsignupnew")
	res, body := h.postJSON(c, "/signup", url.Values{
		"email": {newEmail}, "password": {"long-enough-password"},
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /signup disabled: expected 403, got %d (%s)", res.StatusCode, body)
	}
	if !strings.Contains(body, "forbidden") {
		t.Fatalf("POST /signup disabled: expected stable forbidden code, got %s", body)
	}

	// Anti-enumeration under disabled: the refusal for an EXISTING email
	// must be byte-identical to the refusal for an unknown one — the
	// branch runs before any lookup, and this pins it.
	eres, ebody := h.postJSON(c, "/signup", url.Values{
		"email": {emailAddr}, "password": {"long-enough-password"},
	})
	if eres.StatusCode != res.StatusCode || ebody != body {
		t.Fatalf("disabled signup must not distinguish existing accounts: %d %q vs %d %q",
			eres.StatusCode, ebody, res.StatusCode, body)
	}

	var count int
	if err := h.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE email = $1`, newEmail).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("disabled signup must not create users, found %d rows", count)
	}

	// An existing account still logs in (via magic link — no password set).
	tok, err := issueRawMagicLinkToken(h.pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	lres, _ := browserGet(t, c, h.srv.URL+"/magiclink/confirm?token="+tok)
	if lres.StatusCode != http.StatusFound {
		t.Fatalf("magic link under disabled signup: expected 302, got %d", lres.StatusCode)
	}
}
