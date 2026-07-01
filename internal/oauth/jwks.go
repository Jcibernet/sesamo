package oauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IDTokenClaims are the standard OIDC claims we validate and consume.
type IDTokenClaims struct {
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Exp           int64  `json:"exp"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// jwk is a single JSON Web Key (RSA).
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// jwksCache fetches and caches a provider's JWKS, refreshing on cache
// miss (e.g. after key rotation introduces a new kid).
type jwksCache struct {
	url string
	mu  sync.RWMutex
	// keys maps kid -> parsed RSA public key.
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{url: url, keys: make(map[string]*rsa.PublicKey), ttl: time.Hour}
}

func (c *jwksCache) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	k, ok := c.keys[kid]
	fresh := time.Since(c.fetchedAt) < c.ttl
	c.mu.RUnlock()
	if ok {
		return k, nil
	}
	// Miss or unknown kid: refresh once (handles rotation). Force-refresh
	// even if "fresh" because the kid is unknown.
	_ = fresh
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	c.mu.RLock()
	k, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("oauth: unknown signing key kid=%s", kid)
	}
	return k, nil
}

func (c *jwksCache) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("oauth: fetch jwks: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("oauth: jwks status %d", res.StatusCode)
	}
	var set jwkSet
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		return fmt.Errorf("oauth: decode jwks: %w", err)
	}
	parsed := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := k.toRSA()
		if err != nil {
			continue
		}
		parsed[k.Kid] = pub
	}
	c.mu.Lock()
	c.keys = parsed
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

func (k jwk) toRSA() (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nb)
	// Pad exponent to 8 bytes big-endian.
	var e64 [8]byte
	copy(e64[8-len(eb):], eb)
	e := int(binary.BigEndian.Uint64(e64[:]))
	return &rsa.PublicKey{N: n, E: e}, nil
}

// verifyIDToken validates an RS256 id_token's signature against the
// JWKS, then checks iss, aud, and exp. Returns the parsed claims.
//
// This is the security-critical path: we never trust an id_token's
// payload without verifying the signature and the iss/aud/exp triplet.
func verifyIDToken(ctx context.Context, cache *jwksCache, raw, wantIss, wantAud string) (*IDTokenClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oauth: malformed jwt")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oauth: jwt header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("oauth: jwt header json: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("oauth: unexpected jwt alg %q", header.Alg)
	}

	pub, err := cache.key(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	signed := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oauth: jwt sig: %w", err)
	}
	digest := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("oauth: jwt signature invalid: %w", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oauth: jwt payload: %w", err)
	}
	var claims IDTokenClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("oauth: jwt payload json: %w", err)
	}

	// Issuer may be with or without scheme depending on provider; accept
	// exact match or https-prefixed match.
	if claims.Iss != wantIss && claims.Iss != "https://"+wantIss {
		return nil, fmt.Errorf("oauth: bad issuer %q", claims.Iss)
	}
	if claims.Aud != wantAud {
		return nil, fmt.Errorf("oauth: bad audience %q", claims.Aud)
	}
	if time.Now().Unix() >= claims.Exp {
		return nil, fmt.Errorf("oauth: id_token expired")
	}
	return &claims, nil
}
