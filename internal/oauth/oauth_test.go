package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPKCEChallengeDerivation(t *testing.T) {
	p := NewPKCE()
	if p.Verifier == "" || p.Challenge == "" {
		t.Fatal("empty pkce")
	}
	// Challenge must equal base64url(sha256(verifier)).
	sum := sha256.Sum256([]byte(p.Verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if p.Challenge != want {
		t.Fatalf("challenge mismatch: %s != %s", p.Challenge, want)
	}
	if pkceChallengeFromVerifier(p.Verifier) != p.Challenge {
		t.Fatal("deterministic derivation broken")
	}
}

// signRS256 builds a signed JWT for the test JWKS server.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksServer serves a single RSA public key as a JWKS.
func jwksServer(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	eBytes := big.NewInt(int64(key.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	body, _ := json.Marshal(jwkSet{Keys: []jwk{{
		Kid: kid, Kty: "RSA", Alg: "RS256", N: n, E: e,
	}}})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
}

func TestVerifyIDTokenHappyPath(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, key, "kid1")
	defer srv.Close()
	cache := newJWKSCache(srv.URL)

	raw := signRS256(t, key, "kid1", map[string]any{
		"iss":            "accounts.google.com",
		"aud":            "client-123",
		"sub":            "user-abc",
		"email":          "a@b.com",
		"email_verified": true,
		"exp":            time.Now().Add(time.Hour).Unix(),
	})
	claims, err := verifyIDToken(context.Background(), cache, raw, "accounts.google.com", "client-123")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub != "user-abc" || claims.Email != "a@b.com" {
		t.Fatalf("bad claims: %+v", claims)
	}
}

func TestVerifyIDTokenRejectsBadAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, key, "kid1")
	defer srv.Close()
	cache := newJWKSCache(srv.URL)

	raw := signRS256(t, key, "kid1", map[string]any{
		"iss": "accounts.google.com", "aud": "WRONG", "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := verifyIDToken(context.Background(), cache, raw, "accounts.google.com", "client-123"); err == nil {
		t.Fatal("expected audience rejection")
	}
}

func TestVerifyIDTokenRejectsBadIssuer(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, key, "kid1")
	defer srv.Close()
	cache := newJWKSCache(srv.URL)

	raw := signRS256(t, key, "kid1", map[string]any{
		"iss": "evil.com", "aud": "client-123", "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := verifyIDToken(context.Background(), cache, raw, "accounts.google.com", "client-123"); err == nil {
		t.Fatal("expected issuer rejection")
	}
}

func TestVerifyIDTokenRejectsExpired(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, key, "kid1")
	defer srv.Close()
	cache := newJWKSCache(srv.URL)

	raw := signRS256(t, key, "kid1", map[string]any{
		"iss": "accounts.google.com", "aud": "client-123", "sub": "x",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	if _, err := verifyIDToken(context.Background(), cache, raw, "accounts.google.com", "client-123"); err == nil {
		t.Fatal("expected expiry rejection")
	}
}

func TestVerifyIDTokenRejectsTamperedSignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, key, "kid1") // server publishes the REAL key
	defer srv.Close()
	cache := newJWKSCache(srv.URL)

	// Token signed by the attacker's key, not the published one.
	raw := signRS256(t, attacker, "kid1", map[string]any{
		"iss": "accounts.google.com", "aud": "client-123", "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := verifyIDToken(context.Background(), cache, raw, "accounts.google.com", "client-123"); err == nil {
		t.Fatal("expected signature rejection")
	}
}
