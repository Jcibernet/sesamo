package http

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jcibernet/sesamo/internal/config"
)

// descriptorTestConfig is a fully-populated config whose secret fields
// carry recognizable sentinels, so a leak test can look for the exact
// values instead of guessing at field names.
func descriptorTestConfig() *config.Config {
	return &config.Config{
		Env:                     config.EnvProduction,
		ProjectSlug:             "marketmaker-prod",
		ProjectDisplayName:      "Marketmaker",
		Version:                 "v1.2.3",
		DatabaseURL:             "postgres://leak:LEAK-DSN@db/leak?sslmode=require",
		BaseURL:                 "https://auth.example.com",
		CookieName:              "sid",
		CookieSecure:            true,
		SessionLifetime:         30 * 24 * time.Hour,
		SessionMaxLifetime:      90 * 24 * time.Hour,
		RollingRenewalThreshold: 15 * time.Minute,
		ServiceToken:            "LEAK-SERVICE-TOKEN",
		AdminAPIKey:             "LEAK-ADMIN-KEY",
		RedirectOrigins:         []string{"https://leak-redirect.example.com"},
		Signup:                  config.SignupPublic,
		EmailProvider:           "resend",
		EmailFrom:               "auth@example.com",
		EmailAPIKey:             "LEAK-EMAIL-KEY",
		EmailOutboxKeys:         "k1:LEAK-OUTBOX-KEY",
		ResendWebhookSecret:     "whsec_LEAK-WEBHOOK",
	}
}

// TestDescriptorErrorCatalogMatchesConstants is the anti-drift test the
// design calls for: the descriptor's "errors" array must be exactly the
// set of stable codes the handlers emit. The expected set is spelled out
// from the constants (not from stableErrorCodes) so that dropping a code
// from the slice fails here instead of silently shrinking the published
// catalog.
func TestDescriptorErrorCatalogMatchesConstants(t *testing.T) {
	want := []string{
		codeInvalidCredentials,
		codeInvalidRequest,
		codeRateLimited,
		codeUnauthorized,
		codeForbidden,
		codeNotFound,
		codeInternal,
		codeStateMismatch,
		codeOAuthFailed,
		codeCSRFFailed,
	}
	got := slices.Clone(buildDescriptor(descriptorTestConfig(), nil).Errors)

	sortedWant, sortedGot := slices.Clone(want), slices.Clone(got)
	slices.Sort(sortedWant)
	slices.Sort(sortedGot)
	if !slices.Equal(sortedGot, sortedWant) {
		t.Errorf("descriptor errors = %v, want exactly %v", got, want)
	}
	// Duplicates would still pass a set comparison but corrupt the
	// published catalog.
	if len(slices.Compact(sortedGot)) != len(sortedGot) {
		t.Errorf("descriptor errors contains duplicates: %v", got)
	}
}

// TestDescriptorErrorCatalogServedOverHTTP proves the anti-drift
// guarantee holds through the real handler, not only the builder.
func TestDescriptorErrorCatalogServedOverHTTP(t *testing.T) {
	h := newHarness(t)
	var doc descriptorDoc
	h.getJSON(t, "/.well-known/sesamo", &doc)

	if !slices.Equal(doc.Errors, stableErrorCodes) {
		t.Errorf("served errors = %v, want %v", doc.Errors, stableErrorCodes)
	}
}

// TestDescriptorCapabilities pins that capabilities describe what this
// deployment can actually do: an OAuth provider appears only when it is
// configured, and the signup policy is reported verbatim.
func TestDescriptorCapabilities(t *testing.T) {
	cases := []struct {
		name          string
		mutate        func(*config.Config)
		wantProviders []string
		wantSignup    string
	}{
		{
			name:          "no providers configured",
			mutate:        func(cfg *config.Config) { cfg.Google = config.OAuthProviderConfig{} },
			wantProviders: []string{},
			wantSignup:    config.SignupPublic,
		},
		{
			name: "google enabled",
			mutate: func(cfg *config.Config) {
				cfg.Google = config.OAuthProviderConfig{
					ClientID:     "google-id",
					ClientSecret: "google-secret",
					RedirectURI:  "https://auth.example.com/auth/google/callback",
				}
			},
			wantProviders: []string{"google"},
			wantSignup:    config.SignupPublic,
		},
		{
			name: "github and google enabled, signup disabled",
			mutate: func(cfg *config.Config) {
				cfg.Google = config.OAuthProviderConfig{
					ClientID:     "google-id",
					ClientSecret: "google-secret",
					RedirectURI:  "https://auth.example.com/auth/google/callback",
				}
				cfg.GitHub = config.OAuthProviderConfig{
					ClientID:     "github-id",
					ClientSecret: "github-secret",
					RedirectURI:  "https://auth.example.com/auth/github/callback",
				}
				cfg.Signup = config.SignupDisabled
			},
			wantProviders: []string{"github", "google"},
			wantSignup:    config.SignupDisabled,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := descriptorTestConfig()
			tc.mutate(cfg)
			reg, err := buildProviders(cfg)
			if err != nil {
				t.Fatalf("buildProviders: %v", err)
			}

			caps := buildDescriptor(cfg, reg.Names()).Capabilities
			if !slices.Equal(caps.OAuthProviders, tc.wantProviders) {
				t.Errorf("oauth_providers = %v, want %v", caps.OAuthProviders, tc.wantProviders)
			}
			if caps.Signup != tc.wantSignup {
				t.Errorf("signup = %q, want %q", caps.Signup, tc.wantSignup)
			}
			if !caps.Password || !caps.MagicLink {
				t.Errorf("password/magic_link = %v/%v, want true/true", caps.Password, caps.MagicLink)
			}
		})
	}
}

// TestDescriptorOAuthProvidersSortedAndNonNull guards the two encoding
// properties the document depends on: Registry.Names() iterates a map,
// so an unsorted copy would make the cached descriptor differ per boot,
// and a nil slice would serialize as null instead of [].
func TestDescriptorOAuthProvidersSortedAndNonNull(t *testing.T) {
	doc := buildDescriptor(descriptorTestConfig(), []string{"google", "apple", "github"})
	if want := []string{"apple", "github", "google"}; !slices.Equal(doc.Capabilities.OAuthProviders, want) {
		t.Errorf("oauth_providers = %v, want %v (sorted)", doc.Capabilities.OAuthProviders, want)
	}

	body, err := json.Marshal(buildDescriptor(descriptorTestConfig(), nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"oauth_providers":[]`) {
		t.Errorf("empty provider set did not serialize as []: %s", body)
	}
}

// TestDescriptorSessionContract pins the session facts a consuming
// gateway integrates against.
func TestDescriptorSessionContract(t *testing.T) {
	cfg := descriptorTestConfig()
	got := buildDescriptor(cfg, nil).Session

	want := descriptorSession{
		CookieName:              "sid",
		Secure:                  true,
		SameSite:                "Lax",
		LifetimeSeconds:         int64((30 * 24 * time.Hour).Seconds()),
		AbsoluteLifetimeSeconds: int64((90 * 24 * time.Hour).Seconds()),
		RenewalHeader:           "X-Session-Renewed",
	}
	if got != want {
		t.Errorf("session = %+v, want %+v", got, want)
	}
}

// TestDescriptorLeaksNoSecrets is the reason this endpoint can be
// unauthenticated. Every sensitive config value carries a sentinel; none
// may appear anywhere in the serialized document.
func TestDescriptorLeaksNoSecrets(t *testing.T) {
	cfg := descriptorTestConfig()
	cfg.Google = config.OAuthProviderConfig{
		ClientID:     "google-id",
		ClientSecret: "LEAK-GOOGLE-SECRET",
		RedirectURI:  "https://auth.example.com/auth/google/callback",
	}
	reg, err := buildProviders(cfg)
	if err != nil {
		t.Fatalf("buildProviders: %v", err)
	}
	body, err := json.Marshal(buildDescriptor(cfg, reg.Names()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	for name, secret := range map[string]string{
		"DatabaseURL":         cfg.DatabaseURL,
		"ServiceToken":        cfg.ServiceToken,
		"AdminAPIKey":         cfg.AdminAPIKey,
		"EmailAPIKey":         cfg.EmailAPIKey,
		"EmailOutboxKeys":     cfg.EmailOutboxKeys,
		"ResendWebhookSecret": cfg.ResendWebhookSecret,
		"RedirectOrigins":     cfg.RedirectOrigins[0],
		"GoogleClientSecret":  cfg.Google.ClientSecret,
	} {
		if strings.Contains(string(body), secret) {
			t.Errorf("descriptor leaks %s (%q) in: %s", name, secret, body)
		}
	}
}

// TestDescriptorEndpointsAreServed keeps the published route map honest:
// every path the descriptor advertises must be routed. Wildcards are
// filled with a concrete value, and the assertion is only "not 404" —
// asserting status codes would duplicate the flow tests.
func TestDescriptorEndpointsAreServed(t *testing.T) {
	h := newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.Google = config.OAuthProviderConfig{
			ClientID:     "google-id",
			ClientSecret: "google-secret",
			RedirectURI:  "http://127.0.0.1/auth/google/callback",
		}
	})

	var doc descriptorDoc
	h.getJSON(t, "/.well-known/sesamo", &doc)

	v := reflect.ValueOf(doc.Endpoints)
	for i := range v.NumField() {
		ep := v.Field(i).Interface().(descriptorEndpoint)
		name := v.Type().Field(i).Name
		path := strings.NewReplacer(
			"{provider}", "google",
			"{id}", "00000000-0000-0000-0000-000000000000",
		).Replace(ep.Path)

		req, err := http.NewRequest(ep.Method, h.srv.URL+path, nil)
		if err != nil {
			t.Fatalf("%s: new request: %v", name, err)
		}
		resp, err := h.client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", ep.Method, path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			t.Errorf("descriptor advertises %s (%s %s) but the mux answered %d",
				name, ep.Method, ep.Path, resp.StatusCode)
		}
	}
}

// TestDescriptorOpenAPIDocument checks the spec is valid JSON, carries
// the runtime version, and documents the integration hot path.
func TestDescriptorOpenAPIDocument(t *testing.T) {
	var spec struct {
		OpenAPI string `json:"openapi"`
		Info    struct {
			Version string `json:"version"`
		} `json:"info"`
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openAPIDocument("v9.9.9"), &spec); err != nil {
		t.Fatalf("openapi document is not valid JSON: %v", err)
	}
	if !strings.HasPrefix(spec.OpenAPI, "3.1") {
		t.Errorf("openapi = %q, want 3.1.x", spec.OpenAPI)
	}
	if spec.Info.Version != "v9.9.9" {
		t.Errorf("info.version = %q, want the injected runtime version", spec.Info.Version)
	}
	for _, path := range []string{"/v1/introspect", "/login", "/v1/admin/users/{id}"} {
		if _, ok := spec.Paths[path]; !ok {
			t.Errorf("openapi document does not document %s", path)
		}
	}

	// An unstamped build must still produce a valid version, and a
	// hostile -ldflags value must not be able to break the JSON.
	if err := json.Unmarshal(openAPIDocument(""), &spec); err != nil {
		t.Fatalf("empty version broke the document: %v", err)
	}
	if spec.Info.Version != "dev" {
		t.Errorf("info.version = %q for an unstamped build, want \"dev\"", spec.Info.Version)
	}
	if err := json.Unmarshal(openAPIDocument(`", "x": "`), &spec); err != nil {
		t.Fatalf("version with quotes broke the document: %v", err)
	}
}

// TestDescriptorOpenAPIServed asserts the endpoint returns the parsed
// document as JSON.
func TestDescriptorOpenAPIServed(t *testing.T) {
	h := newHarness(t)
	resp, err := h.client().Get(h.srv.URL + "/openapi.json")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var spec map[string]any
	if err := json.Unmarshal(body, &spec); err != nil {
		t.Fatalf("served openapi is not valid JSON: %v", err)
	}
	if !strings.Contains(string(body), "/v1/introspect") {
		t.Error("served openapi does not mention /v1/introspect")
	}
}

// TestDescriptorLLMsTxt checks the agent briefing is served as plain
// text and stays short enough to be worth reading in full.
func TestDescriptorLLMsTxt(t *testing.T) {
	if n := strings.Count(llmsTxt, "\n"); n > 60 {
		t.Errorf("llms.txt has %d lines, want <= 60 (it is a briefing, not a manual)", n)
	}

	h := newHarness(t)
	resp, err := h.client().Get(h.srv.URL + "/llms.txt")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	// The three facts an agent cannot integrate without.
	for _, want := range []string{"/.well-known/sesamo", "/v1/introspect", csrfHeader} {
		if !strings.Contains(string(body), want) {
			t.Errorf("llms.txt does not mention %q", want)
		}
	}
	// Relative paths only: the descriptor must not pin a public origin.
	if strings.Contains(string(body), "https://auth.example") {
		t.Error("llms.txt hardcodes a domain; it must reference relative paths")
	}
}

// TestDescribeJSONMatchesEndpoint is the contract behind `sesamo
// describe`: the CLI and the endpoint must describe the same deployment.
// Formatting differs (the CLI indents), so the comparison is on the
// decoded documents.
func TestDescribeJSONMatchesEndpoint(t *testing.T) {
	cfg := descriptorTestConfig()
	cfg.Google = config.OAuthProviderConfig{
		ClientID:     "google-id",
		ClientSecret: "google-secret",
		RedirectURI:  "https://auth.example.com/auth/google/callback",
	}

	cli, err := DescribeJSON(cfg)
	if err != nil {
		t.Fatalf("DescribeJSON: %v", err)
	}
	reg, err := buildProviders(cfg)
	if err != nil {
		t.Fatalf("buildProviders: %v", err)
	}
	served, err := json.Marshal(buildDescriptor(cfg, reg.Names()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var fromCLI, fromEndpoint any
	if err := json.Unmarshal(cli, &fromCLI); err != nil {
		t.Fatalf("CLI output is not valid JSON: %v", err)
	}
	if err := json.Unmarshal(served, &fromEndpoint); err != nil {
		t.Fatalf("endpoint body is not valid JSON: %v", err)
	}
	if !reflect.DeepEqual(fromCLI, fromEndpoint) {
		t.Errorf("`sesamo describe` differs from the endpoint:\nCLI:      %s\nendpoint: %s", cli, served)
	}
	if !strings.Contains(string(cli), "\n  ") {
		t.Error("DescribeJSON output is not indented; it is read on a terminal")
	}
}

// TestDescribeJSONNeedsNoDatabase documents the property that makes the
// subcommand usable from a container without DB credentials: an
// unreachable (indeed nonsensical) DSN changes nothing.
func TestDescribeJSONNeedsNoDatabase(t *testing.T) {
	cfg := descriptorTestConfig()
	cfg.DatabaseURL = "postgres://nobody@127.0.0.1:1/nowhere"
	if _, err := DescribeJSON(cfg); err != nil {
		t.Fatalf("DescribeJSON touched the database or failed: %v", err)
	}
}

// TestDescriptorServedShape verifies the served document over HTTP:
// identity fields, cacheability, and the version main stamps in.
func TestDescriptorServedShape(t *testing.T) {
	h := newHarnessWithConfig(t, func(cfg *config.Config) {
		cfg.ProjectSlug = "marketmaker-prod"
		cfg.ProjectDisplayName = "Marketmaker"
		cfg.Version = "v1.2.3"
		cfg.Signup = config.SignupPublic
	})

	resp, err := h.client().Get(h.srv.URL + "/.well-known/sesamo")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=300") {
		t.Errorf("Cache-Control = %q, want a short max-age", cc)
	}

	var doc descriptorDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if doc.SchemaVersion != descriptorSchemaVersion {
		t.Errorf("schema_version = %d, want %d", doc.SchemaVersion, descriptorSchemaVersion)
	}
	if doc.Service.Name != "sesamo" || doc.Service.Version != "v1.2.3" {
		t.Errorf("service = %+v, want {sesamo v1.2.3}", doc.Service)
	}
	if doc.Project.Slug != "marketmaker-prod" || doc.Project.DisplayName != "Marketmaker" {
		t.Errorf("project = %+v", doc.Project)
	}
	if doc.Endpoints.Introspect.Auth != authServiceToken {
		t.Errorf("introspect auth = %q, want %q", doc.Endpoints.Introspect.Auth, authServiceToken)
	}
	if doc.Endpoints.AdminDisable.Auth != authAdminKey {
		t.Errorf("admin_disable auth = %q, want %q", doc.Endpoints.AdminDisable.Auth, authAdminKey)
	}
	if doc.Endpoints.Login.Auth != "" {
		t.Errorf("login auth = %q, want empty (unauthenticated)", doc.Endpoints.Login.Auth)
	}
}

// getJSON fetches path from the harness and decodes the JSON body.
func (h *harness) getJSON(t *testing.T, path string, dst any) {
	t.Helper()
	resp, err := h.client().Get(h.srv.URL + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get %s: status = %d, want 200", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}
