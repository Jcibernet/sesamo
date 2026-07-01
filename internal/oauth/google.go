package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jcibernet/sesamo/internal/user"
)

const (
	googleAuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL     = "https://oauth2.googleapis.com/token"
	googleJWKSURL      = "https://www.googleapis.com/oauth2/v3/certs"
	googleIssuer       = "accounts.google.com"
)

// Google implements Provider for Google Sign-In using the id_token
// (RS256, verified against Google's JWKS) as the source of identity.
type Google struct {
	clientID     string
	clientSecret string
	redirectURI  string
	jwks         *jwksCache
}

// NewGoogle constructs the Google provider.
func NewGoogle(clientID, clientSecret, redirectURI string) *Google {
	return &Google{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
		jwks:         newJWKSCache(googleJWKSURL),
	}
}

// Name returns "google".
func (g *Google) Name() string { return "google" }

// AuthorizeURL builds the consent redirect with PKCE S256 + state.
func (g *Google) AuthorizeURL(state, codeVerifier string) string {
	pkce := pkceChallengeFromVerifier(codeVerifier)
	q := url.Values{
		"client_id":             {g.clientID},
		"redirect_uri":          {g.redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"code_challenge":        {pkce},
		"code_challenge_method": {"S256"},
		"access_type":           {"online"},
		"prompt":                {"select_account"},
	}
	return googleAuthorizeURL + "?" + q.Encode()
}

// Exchange swaps the code for tokens and verifies the id_token.
func (g *Google) Exchange(ctx context.Context, code, codeVerifier string) (user.OAuthProfile, error) {
	form := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {g.redirectURI},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return user.OAuthProfile{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return user.OAuthProfile{}, fmt.Errorf("google token exchange: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return user.OAuthProfile{}, fmt.Errorf("google token status %d", res.StatusCode)
	}

	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&tok); err != nil {
		return user.OAuthProfile{}, fmt.Errorf("google token decode: %w", err)
	}
	if tok.IDToken == "" {
		return user.OAuthProfile{}, fmt.Errorf("google response missing id_token")
	}

	claims, err := verifyIDToken(ctx, g.jwks, tok.IDToken, googleIssuer, g.clientID)
	if err != nil {
		return user.OAuthProfile{}, err
	}
	if !claims.EmailVerified {
		return user.OAuthProfile{}, fmt.Errorf("google email not verified")
	}

	return user.OAuthProfile{
		Provider:      "google",
		Sub:           claims.Sub,
		Email:         claims.Email,
		EmailVerified: true,
		Name:          strPtr(claims.Name),
		PictureURL:    strPtr(claims.Picture),
	}, nil
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
