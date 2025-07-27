package keycloaklib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type KeycloakAdmin struct {
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

func getAdminToken(ctx context.Context, config *Config) (*tokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", config.URL, config.Realm)
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToReadResponse, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(ErrFailedToGetToken, resp.StatusCode, body)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf(ErrFailedToParseToken, err)
	}
	if tok.AccessToken == emptyString {
		return nil, fmt.Errorf(ErrNoAccessToken)
	}
	return &tok, nil
}

func (ka *KeycloakAdmin) refreshAdminToken(ctx context.Context) error {
	if ka.refreshToken == emptyString {
		return fmt.Errorf(ErrNoRefreshToken)
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", ka.config.URL, ka.config.Realm)
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", ka.config.ClientID)
	data.Set("client_secret", ka.config.ClientSecret)
	data.Set("refresh_token", ka.refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf(ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ka.client.Do(req)
	if err != nil {
		return fmt.Errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf(ErrFailedToReadResponse, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(ErrFailedToRefreshToken, resp.StatusCode, body)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return fmt.Errorf(ErrFailedToParseToken, err)
	}
	if tok.AccessToken == emptyString {
		return fmt.Errorf(ErrNoAccessTokenInRefresh)
	}

	ka.accessToken = tok.AccessToken
	ka.refreshToken = tok.RefreshToken
	ka.expiry = time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - 30*time.Second)
	return nil
}

func (ka *KeycloakAdmin) ensureTokenValid(ctx context.Context) error {
	ka.mu.Lock()
	defer ka.mu.Unlock()

	if time.Now().Before(ka.expiry) {
		return nil
	}

	if err := ka.refreshAdminToken(ctx); err == nil {
		return nil
	}

	tok, err := getAdminToken(ctx, ka.config)
	if err != nil {
		return fmt.Errorf(ErrTokenRefreshFailed, err)
	}
	ka.accessToken = tok.AccessToken
	ka.refreshToken = tok.RefreshToken
	ka.expiry = time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - 30*time.Second)
	return nil
}

func NewKeycloakAdmin(ctx context.Context, config *Config) (*KeycloakAdmin, error) {
	if config == nil {
		return nil, fmt.Errorf(ErrConfigRequired)
	}
	if config.ClientID == emptyString || config.ClientSecret == emptyString {
		return nil, fmt.Errorf(ErrClientIDAndSecretRequired)
	}

	tok, err := getAdminToken(ctx, config)
	if err != nil {
		return nil, err
	}

	expiry := time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - 30*time.Second)

	return &KeycloakAdmin{
		client:       http.DefaultClient,
		accessToken:  tok.AccessToken,
		refreshToken: tok.RefreshToken,
		expiry:       expiry,
		config:       config,
		baseURL:      fmt.Sprintf("%s/admin/realms/%s/users", config.URL, config.Realm),
	}, nil
}

func (ka *KeycloakAdmin) CreateUser(ctx context.Context, params UserCreateParams) (string, error) {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return emptyString, fmt.Errorf(ErrTokenRefreshFailed, err)
	}

	enabled := true
	if params.Enabled != nil {
		enabled = *params.Enabled
	}
	emailVerified := false
	if params.EmailVerified != nil {
		emailVerified = *params.EmailVerified
	}

	user := User{
		Username:      params.Username,
		Email:         params.Email,
		FirstName:     params.FirstName,
		LastName:      params.LastName,
		Enabled:       &enabled,
		EmailVerified: &emailVerified,
		Attributes:    params.Attributes,
	}

	if params.Password != emptyString {
		cred := Credential{
			Type:      "password",
			Value:     params.Password,
			Temporary: params.TemporaryPass,
		}
		user.Credentials = []Credential{cred}
	}

	jsonBody, err := json.Marshal(user)
	if err != nil {
		return emptyString, fmt.Errorf(ErrFailedToMarshalUser, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ka.baseURL, bytes.NewReader(jsonBody))
	if err != nil {
		return emptyString, fmt.Errorf(ErrFailedToCreateUserRequest, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return emptyString, fmt.Errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return emptyString, fmt.Errorf(ErrFailedToCreateUser, resp.StatusCode, body)
	}

	location := resp.Header.Get("Location")
	if location == emptyString {
		return emptyString, fmt.Errorf(ErrNoLocationHeader)
	}
	parts := strings.Split(location, "/")
	if len(parts) < 2 {
		return emptyString, fmt.Errorf(ErrInvalidLocationHeader)
	}
	userID := parts[len(parts)-1]

	return userID, nil
}

func (ka *KeycloakAdmin) GetUserByID(ctx context.Context, userID string) (*User, error) {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return nil, fmt.Errorf(ErrTokenRefreshFailed, err)
	}

	url := fmt.Sprintf("%s/%s", ka.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToGetUserRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToExecuteGetUser, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf(ErrFailedToGetUser, resp.StatusCode, body)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf(ErrFailedToDecodeUser, err)
	}
	return &user, nil
}

func (ka *KeycloakAdmin) DeleteUser(ctx context.Context, userID string) error {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return fmt.Errorf(ErrTokenRefreshFailed, err)
	}

	url := fmt.Sprintf("%s/%s", ka.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf(ErrFailedToDeleteUserRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return fmt.Errorf(ErrFailedToExecuteDeleteUser, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf(ErrFailedToDeleteUser, resp.StatusCode, body)
	}
	return nil
}

func (ka *KeycloakAdmin) Login(ctx context.Context, username, password string, scopes []string) (*oauth2.Token, error) {
	if username == emptyString || password == emptyString {
		return nil, fmt.Errorf(ErrUsernamePasswordRequired)
	}
	clientID := ka.config.ClientID
	if ka.config.OtherClientID != emptyString {
		clientID = ka.config.OtherClientID
	}
	if clientID == emptyString {
		return nil, fmt.Errorf(ErrClientIDRequired)
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", ka.config.URL, ka.config.Realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", clientID)
	if ka.config.ClientSecret != emptyString && ka.config.OtherClientID == emptyString {
		data.Set("client_secret", ka.config.ClientSecret)
	}
	data.Set("username", username)
	data.Set("password", password)
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToReadResponse, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(ErrFailedToObtainLoginToken, resp.StatusCode, body)
	}

	var token oauth2.Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf(ErrFailedToParseToken, err)
	}

	if token.AccessToken == emptyString {
		return nil, fmt.Errorf(ErrNoAccessToken)
	}

	return &token, nil
}
