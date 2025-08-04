package keycloaklib

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

type KeycloakClient struct {
	mu           sync.Mutex
	client       *http.Client
	accessToken  string
	refreshToken string
	expiry       time.Time
	config       *Config
	baseURL      string
}

type UserCreateParams struct {
	Username        string
	Email           string
	FirstName       string
	LastName        string
	Enabled         bool
	EmailVerified   bool
	Attributes      map[string][]string
	RequiredActions []string
	Credentials     []Credential
}

type UserCreateParamsBuilder struct {
	params UserCreateParams
}

func NewUserCreateParamsBuilder() *UserCreateParamsBuilder {
	return &UserCreateParamsBuilder{
		params: UserCreateParams{
			Enabled:       true,
			EmailVerified: true,
		},
	}
}

func (b *UserCreateParamsBuilder) WithUsername(username string) *UserCreateParamsBuilder {
	b.params.Username = username
	return b
}

func (b *UserCreateParamsBuilder) WithEmail(email string) *UserCreateParamsBuilder {
	b.params.Email = email
	return b
}

func (b *UserCreateParamsBuilder) WithFirstName(firstName string) *UserCreateParamsBuilder {
	b.params.FirstName = firstName
	return b
}

func (b *UserCreateParamsBuilder) WithLastName(lastName string) *UserCreateParamsBuilder {
	b.params.LastName = lastName
	return b
}

func (b *UserCreateParamsBuilder) WithEnabled(enabled bool) *UserCreateParamsBuilder {
	b.params.Enabled = enabled
	return b
}

func (b *UserCreateParamsBuilder) WithEmailVerified(verified bool) *UserCreateParamsBuilder {
	b.params.EmailVerified = verified
	return b
}

func (b *UserCreateParamsBuilder) WithAttributes(attributes map[string][]string) *UserCreateParamsBuilder {
	b.params.Attributes = attributes
	return b
}

func (b *UserCreateParamsBuilder) AddCredential(cred Credential) *UserCreateParamsBuilder {
	b.params.Credentials = append(b.params.Credentials, cred)
	return b
}

func (b *UserCreateParamsBuilder) WithRequiredActions(actions []string) *UserCreateParamsBuilder {
	b.params.RequiredActions = actions
	return b
}

func (b *UserCreateParamsBuilder) Build() (UserCreateParams, error) {
	if b.params.Username == emptyString || b.params.Email == emptyString {
		return UserCreateParams{}, errors.New(ErrUsernameAndEmailRequired)
	}
	return b.params, nil
}

type User struct {
	ID              string              `json:"id,omitempty"`
	Username        string              `json:"username,omitempty"`
	Email           string              `json:"email,omitempty"`
	FirstName       string              `json:"firstName,omitempty"`
	LastName        string              `json:"lastName,omitempty"`
	Enabled         *bool               `json:"enabled,omitempty"`
	EmailVerified   *bool               `json:"emailVerified,omitempty"`
	Attributes      map[string][]string `json:"attributes,omitempty"`
	RequiredActions []string            `json:"required_actions,omitempty"`
	Credentials     []Credential        `json:"credentials,omitempty"`
}

type Client struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
}

type Role struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Composite   bool                `json:"composite"`
	ClientRole  bool                `json:"clientRole"`
	ContainerId string              `json:"containerId"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
}

type Credential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}
