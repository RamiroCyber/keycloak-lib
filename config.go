package keycloaklib

import (
	"context"
	"errors"
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

type ConfigBuilder struct {
	config Config
}

func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{}
}

func (b *ConfigBuilder) WithURL(url string) *ConfigBuilder {
	b.config.URL = url
	return b
}

func (b *ConfigBuilder) WithRealm(realm string) *ConfigBuilder {
	b.config.Realm = realm
	return b
}

func (b *ConfigBuilder) WithClientID(clientID string) *ConfigBuilder {
	b.config.ClientID = clientID
	return b
}

func (b *ConfigBuilder) WithClientSecret(clientSecret string) *ConfigBuilder {
	b.config.ClientSecret = clientSecret
	return b
}

func (b *ConfigBuilder) WithPublicClientID(publicClientID string) *ConfigBuilder {
	b.config.PublicClientID = publicClientID
	return b
}

func (b *ConfigBuilder) Build() (*Config, error) {
	if b.config.URL == emptyString {
		return nil, errors.New(ErrKeycloakURLRequired)
	}
	if b.config.Realm == emptyString {
		return nil, errors.New(ErrKeycloakRealmRequired)
	}
	if b.config.ClientID == emptyString {
		return nil, errors.New(ErrKeycloakClientIDRequired)
	}
	if b.config.ClientSecret == emptyString {
		return nil, errors.New(ErrKeycloakClientSecretRequired)
	}
	return &b.config, nil
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
