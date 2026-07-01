package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jcibernet/sesamo/internal/user"
)

const (
	appleAuthorizeURL = "https://appleid.apple.com/auth/authorize"
	appleTokenURL     = "https://appleid.apple.com/auth/token"
	appleJWKSURL      = "https://appleid.apple.com/auth/keys"
	appleIssuer       = "https://appleid.apple.com"
)

// Apple implements Provider for Sign in with Apple. Apple requires the
// client_secret to be a short-lived ES256 JWT signed with your private
// key; identity comes from the id_token verified against Apple's JWKS.
type Apple struct {
	clientID    string // Services ID, also the id_token audience
	teamID      string
	keyID       string
	privateKey  *ecdsa.PrivateKey
	redirectURI string
	jwks        *jwksCache
}

// NewApple constructs the Apple provider, parsing the PEM private key.
func NewApple(clientID, teamID, keyID, privateKeyPEM, redirectURI string) (*Apple, error) {
	key, err := parseECPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("apple: parse private key: %w", err)
	}
	return &Apple{
		clientID:    clientID,
		teamID:      teamID,
		keyID:       keyID,
		privateKey:  key,
		redirectURI: redirectURI,
		jwks:        newJWKSCache(appleJWKSURL),
	}, nil
}

// Name returns "apple".
func (a *Apple) Name() string { return "apple" }

// AuthorizeURL builds the consent redirect. Apple requires response_mode
// form_post when scopes are requested; we keep it simple with state+PKCE.
func (a *Apple) AuthorizeURL(state, codeVerifier string) string {
	q := url.Values{
		"client_id":             {a.clientID},
		"redirect_uri":          {a.redirectURI},
		"response_type":         {"code"},
		"scope":                 {"name email"},
		"state":                 {state},
		"response_mode":         {"query"},
		"code_challenge":        {pkceChallengeFromVerifier(codeVerifier)},
		"code_challenge_method": {"S256"},
	}
	return appleAuthorizeURL + "?" + q.Encode()
}

// Exchange swaps the code for tokens (signing a fresh client_secret JWT)
// and verifies the returned id_token.
func (a *Apple) Exchange(ctx context.Context, code, codeVerifier string) (user.OAuthProfile, error) {
	secret, err := a.clientSecretJWT()
	if err != nil {
		return user.OAuthProfile{}, err
	}
	form := url.Values{
		"client_id":     {a.clientID},
		"client_secret": {secret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {a.redirectURI},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, appleTokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return user.OAuthProfile{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return user.OAuthProfile{}, fmt.Errorf("apple token exchange: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return user.OAuthProfile{}, fmt.Errorf("apple token status %d", res.StatusCode)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&tok); err != nil {
		return user.OAuthProfile{}, fmt.Errorf("apple token decode: %w", err)
	}
	if tok.IDToken == "" {
		return user.OAuthProfile{}, fmt.Errorf("apple response missing id_token")
	}

	claims, err := verifyIDToken(ctx, a.jwks, tok.IDToken, appleIssuer, a.clientID)
	if err != nil {
		return user.OAuthProfile{}, err
	}
	if !claims.EmailVerified {
		return user.OAuthProfile{}, fmt.Errorf("apple email not verified")
	}
	return user.OAuthProfile{
		Provider:      "apple",
		Sub:           claims.Sub,
		Email:         claims.Email,
		EmailVerified: true,
		Name:          strPtr(claims.Name),
	}, nil
}

// clientSecretJWT builds the ES256-signed client_secret Apple requires.
func (a *Apple) clientSecretJWT() (string, error) {
	now := time.Now()
	header := map[string]string{"alg": "ES256", "kid": a.keyID, "typ": "JWT"}
	claims := map[string]any{
		"iss": a.teamID,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"aud": appleIssuer,
		"sub": a.clientID,
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(cb)

	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, a.privateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("apple sign: %w", err)
	}
	// ES256 signature is fixed 64 bytes: r||s, each 32 bytes big-endian.
	sig := make([]byte, 64)
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func parseECPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an EC private key")
	}
	return ec, nil
}
