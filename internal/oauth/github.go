package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/jcibernet/sesamo/internal/user"
)

const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubUserURL      = "https://api.github.com/user"
	githubEmailsURL    = "https://api.github.com/user/emails"
)

// GitHub implements Provider for GitHub. GitHub does not issue an OIDC
// id_token, so identity comes from the authenticated REST API. We still
// use PKCE + state for the authorization code flow.
type GitHub struct {
	clientID     string
	clientSecret string
	redirectURI  string
}

// NewGitHub constructs the GitHub provider.
func NewGitHub(clientID, clientSecret, redirectURI string) *GitHub {
	return &GitHub{clientID: clientID, clientSecret: clientSecret, redirectURI: redirectURI}
}

// Name returns "github".
func (g *GitHub) Name() string { return "github" }

// AuthorizeURL builds the consent redirect with PKCE S256 + state.
func (g *GitHub) AuthorizeURL(state, codeVerifier string) string {
	q := url.Values{
		"client_id":             {g.clientID},
		"redirect_uri":          {g.redirectURI},
		"scope":                 {"read:user user:email"},
		"state":                 {state},
		"code_challenge":        {pkceChallengeFromVerifier(codeVerifier)},
		"code_challenge_method": {"S256"},
	}
	return githubAuthorizeURL + "?" + q.Encode()
}

// Exchange swaps the code for a token and fetches the user + primary
// verified email from the GitHub API.
func (g *GitHub) Exchange(ctx context.Context, code, codeVerifier string) (user.OAuthProfile, error) {
	form := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"redirect_uri":  {g.redirectURI},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, githubTokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return user.OAuthProfile{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := outboundHTTPClient.Do(req)
	if err != nil {
		return user.OAuthProfile{}, fmt.Errorf("github token exchange: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return user.OAuthProfile{}, fmt.Errorf("github token status %d", res.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&tok); err != nil {
		return user.OAuthProfile{}, fmt.Errorf("github token decode: %w", err)
	}
	if tok.AccessToken == "" {
		return user.OAuthProfile{}, fmt.Errorf("github response missing access_token")
	}

	profile, err := g.fetchUser(ctx, tok.AccessToken)
	if err != nil {
		return user.OAuthProfile{}, err
	}
	email, err := g.fetchPrimaryEmail(ctx, tok.AccessToken)
	if err != nil {
		return user.OAuthProfile{}, err
	}
	profile.Email = email
	profile.EmailVerified = true // we only accept verified primary emails
	return profile, nil
}

func (g *GitHub) fetchUser(ctx context.Context, token string) (user.OAuthProfile, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, githubUserURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := outboundHTTPClient.Do(req)
	if err != nil {
		return user.OAuthProfile{}, fmt.Errorf("github user: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return user.OAuthProfile{}, fmt.Errorf("github user status %d", res.StatusCode)
	}
	var u struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&u); err != nil {
		return user.OAuthProfile{}, fmt.Errorf("github user decode: %w", err)
	}
	return user.OAuthProfile{
		Provider:   "github",
		Sub:        fmt.Sprintf("%d", u.ID),
		Name:       strPtr(u.Name),
		PictureURL: strPtr(u.AvatarURL),
	}, nil
}

func (g *GitHub) fetchPrimaryEmail(ctx context.Context, token string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, githubEmailsURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := outboundHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github emails: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github emails status %d", res.StatusCode)
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&emails); err != nil {
		return "", fmt.Errorf("github emails decode: %w", err)
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("github: no verified primary email")
}
