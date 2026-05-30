package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

type Client struct {
	ClientID string
	Scopes   []string

	provider *gooidc.Provider
	verifier *gooidc.IDTokenVerifier
	hc       *http.Client
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

type cache struct {
	mu sync.Mutex
	m  map[string]*Client
}

var clients = &cache{m: map[string]*Client{}}

func Get(ctx context.Context, issuer, clientID string, scopes []string) (*Client, error) {
	clients.mu.Lock()
	defer clients.mu.Unlock()
	key := issuer + "|" + clientID
	if c, ok := clients.m[key]; ok {
		return c, nil
	}
	prov, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery %s: %w", issuer, err)
	}
	c := &Client{
		ClientID: clientID,
		Scopes:   scopes,
		provider: prov,
		verifier: prov.Verifier(&gooidc.Config{ClientID: clientID}),
		hc:       &http.Client{Timeout: 15 * time.Second},
	}
	clients.m[key] = c
	return c, nil
}

func (c *Client) endpoints() (authURL, tokenURL string) {
	e := c.provider.Endpoint()
	return e.AuthURL, e.TokenURL
}

func (c *Client) AuthorizeURL(state, nonce, codeChallenge, redirectURI string) string {
	authURL, _ := c.endpoints()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(c.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(authURL, "?") {
		sep = "&"
	}
	return authURL + sep + q.Encode()
}

func (c *Client) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI, clientAssertion string) (*TokenResponse, error) {
	_, tokenURL := c.endpoints()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.ClientID)
	form.Set("code_verifier", codeVerifier)
	form.Set("client_assertion_type", ClientAssertionTypeJWTBearer)
	form.Set("client_assertion", clientAssertion)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token endpoint %d: %s", resp.StatusCode, string(body))
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("token response missing id_token")
	}
	return &tr, nil
}

type IDClaims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
	Nonce             string   `json:"nonce"`
	Expiry            int64    `json:"exp"`
}

func (c *Client) VerifyIDToken(ctx context.Context, raw string) (*IDClaims, error) {
	tok, err := c.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}
	var claims IDClaims
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	claims.Subject = tok.Subject
	if claims.Expiry == 0 {
		claims.Expiry = tok.Expiry.Unix()
	}
	return &claims, nil
}
