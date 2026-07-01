// Package oauth implements OAuth 2.0 Authorization Code flow with PKCE
// (S256) for Google, GitHub, and Apple. Each provider normalizes to a
// user.OAuthProfile. No third-party OAuth library: net/http + stdlib.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/jcibernet/sesamo/internal/user"
)

// Provider is the common contract for an OAuth identity provider.
type Provider interface {
	// Name returns the provider key stored in identities.provider.
	Name() string
	// AuthorizeURL builds the redirect URL given state and PKCE verifier.
	AuthorizeURL(state, codeVerifier string) string
	// Exchange swaps an authorization code for a normalized profile. The
	// codeVerifier proves PKCE possession.
	Exchange(ctx context.Context, code, codeVerifier string) (user.OAuthProfile, error)
}

// PKCE holds a generated verifier/challenge pair (S256).
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE creates a high-entropy code_verifier and its S256 challenge.
func NewPKCE() PKCE {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("oauth: rand failed: " + err.Error())
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	return PKCE{Verifier: verifier, Challenge: pkceChallengeFromVerifier(verifier)}
}

// pkceChallengeFromVerifier derives the S256 challenge from a verifier.
func pkceChallengeFromVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Registry holds the configured providers by name.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider)}
}

// Add registers a provider.
func (r *Registry) Add(p Provider) {
	r.providers[p.Name()] = p
}

// Get returns a provider by name and whether it exists.
func (r *Registry) Get(name string) (Provider, bool) {
	p, ok := r.providers[name]
	return p, ok
}

// Names returns the registered provider names.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.providers))
	for n := range r.providers {
		out = append(out, n)
	}
	return out
}
