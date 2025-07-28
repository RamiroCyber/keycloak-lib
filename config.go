package keycloaklib

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	URL            string
	Realm          string
	ClientID       string
	ClientSecret   string
	PublicClientID string
}

func NewConfig(url, realm, clientID, clientSecret, otherClientID string) (*Config, error) {
	if url == "" {
		return nil, fmt.Errorf("KEYCLOAK_URL  variable is required")
	}
	if realm == "" {
		return nil, fmt.Errorf("KEYCLOAK_REALM  variable is required")
	}
	if clientID == "" {
		return nil, fmt.Errorf("KEYCLOAK_CLIENT_ID  variable is required")
	}
	if clientSecret == "" {
		return nil, fmt.Errorf("KEYCLOAK_CLIENT_SECRET  variable is required")
	}

	return &Config{
		URL:            url,
		Realm:          realm,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		PublicClientID: otherClientID,
	}, nil
}

func (c *Config) OAuth2Config(redirectURL string, scopes []string) *oauth2.Config {
	clientID := c.ClientID
	if c.PublicClientID != "" {
		clientID = c.PublicClientID
	}
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", c.URL, c.Realm),
			TokenURL: fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.URL, c.Realm),
		},
		Scopes: scopes,
	}
}

func (c *Config) Provider(ctx context.Context) (*oidc.Provider, error) {
	issuer := fmt.Sprintf("%s/realms/%s", c.URL, c.Realm)
	return oidc.NewProvider(ctx, issuer)
}
