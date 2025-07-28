package keycloaklib

import (
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
	Username      string
	Email         string
	FirstName     string
	LastName      string
	Enabled       *bool
	EmailVerified *bool
	Attributes    map[string][]string
	Password      string
	TemporaryPass bool
}

type User struct {
	ID            string              `json:"id,omitempty"`
	Username      string              `json:"username,omitempty"`
	Email         string              `json:"email,omitempty"`
	FirstName     string              `json:"firstName,omitempty"`
	LastName      string              `json:"lastName,omitempty"`
	Enabled       *bool               `json:"enabled,omitempty"`
	EmailVerified *bool               `json:"emailVerified,omitempty"`
	Attributes    map[string][]string `json:"attributes,omitempty"`
	Credentials   []Credential        `json:"credentials,omitempty"`
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
