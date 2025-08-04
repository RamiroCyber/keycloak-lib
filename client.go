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
	"time"
)

func getClientToken(ctx context.Context, config *Config) (*tokenResponse, error) {
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

func (ka *KeycloakClient) refreshAdminToken(ctx context.Context) error {
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

func (ka *KeycloakClient) ensureTokenValid(ctx context.Context) error {
	ka.mu.Lock()
	defer ka.mu.Unlock()

	if time.Now().Before(ka.expiry) {
		return nil
	}

	if err := ka.refreshAdminToken(ctx); err == nil {
		return nil
	}

	tok, err := getClientToken(ctx, ka.config)
	if err != nil {
		return fmt.Errorf(ErrTokenRefreshFailed, err)
	}
	ka.accessToken = tok.AccessToken
	ka.refreshToken = tok.RefreshToken
	ka.expiry = time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - 30*time.Second)
	return nil
}

func NewKeycloakClient(ctx context.Context, config *Config) (*KeycloakClient, error) {
	if config == nil {
		return nil, fmt.Errorf(ErrConfigRequired)
	}
	if config.ClientID == emptyString || config.ClientSecret == emptyString {
		return nil, fmt.Errorf(ErrClientIDAndSecretRequired)
	}

	tok, err := getClientToken(ctx, config)
	if err != nil {
		return nil, err
	}

	expiry := time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - 30*time.Second)

	return &KeycloakClient{
		client:       http.DefaultClient,
		accessToken:  tok.AccessToken,
		refreshToken: tok.RefreshToken,
		expiry:       expiry,
		config:       config,
		baseURL:      fmt.Sprintf("%s/admin/realms/%s/users", config.URL, config.Realm),
	}, nil
}

func (ka *KeycloakClient) CreateUser(ctx context.Context, params UserCreateParams) (string, error) {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return emptyString, fmt.Errorf(ErrTokenRefreshFailed, err)
	}

	enabled := params.Enabled
	emailVerified := params.EmailVerified

	user := User{
		Username:        params.Username,
		Email:           params.Email,
		FirstName:       params.FirstName,
		LastName:        params.LastName,
		Enabled:         &enabled,
		EmailVerified:   &emailVerified,
		Attributes:      params.Attributes,
		RequiredActions: params.RequiredActions,
		Credentials:     params.Credentials,
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

func (ka *KeycloakClient) GetUserByID(ctx context.Context, userID string) (*User, error) {
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

func (ka *KeycloakClient) DeleteUser(ctx context.Context, userID string) error {
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

func (ka *KeycloakClient) Login(ctx context.Context, username, password string, scopes []string) (*oauth2.Token, error) {
	if username == emptyString || password == emptyString {
		return nil, fmt.Errorf(ErrUsernamePasswordRequired)
	}
	clientID := ka.config.ClientID
	if ka.config.PublicClientID != emptyString {
		clientID = ka.config.PublicClientID
	}
	if clientID == emptyString {
		return nil, fmt.Errorf(ErrClientIDRequired)
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", ka.config.URL, ka.config.Realm)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", clientID)
	if ka.config.ClientSecret != emptyString && ka.config.PublicClientID == emptyString {
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

func (ka *KeycloakClient) getClientByClientID(ctx context.Context, clientID string) (*Client, error) {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return nil, fmt.Errorf(ErrTokenRefreshFailed, err)
	}

	clientURL := fmt.Sprintf("%s/admin/realms/%s/clients?clientId=%s", ka.config.URL, ka.config.Realm, url.QueryEscape(clientID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientURL, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToCreateGetClientRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToExecuteGetClient, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf(ErrFailedToGetClient, resp.StatusCode, body)
	}

	var clients []Client
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, fmt.Errorf(ErrFailedToDecodeClients, err)
	}

	if len(clients) == 0 {
		return nil, fmt.Errorf(ErrNoClientFound, clientID)
	}

	return &clients[0], nil
}

func (ka *KeycloakClient) getClientRole(ctx context.Context, clientUUID, roleName string) (*Role, error) {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return nil, fmt.Errorf(ErrTokenRefreshFailed, err)
	}

	roleURL := fmt.Sprintf("%s/admin/realms/%s/clients/%s/roles/%s", ka.config.URL, ka.config.Realm, clientUUID, url.PathEscape(roleName))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, roleURL, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToCreateGetClientRoleRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrFailedToExecuteGetClientRole, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf(ErrFailedToGetClientRole, resp.StatusCode, body)
	}

	var role Role
	if err := json.NewDecoder(resp.Body).Decode(&role); err != nil {
		return nil, fmt.Errorf(ErrFailedToDecodeClientRole, err)
	}
	return &role, nil
}

func (ka *KeycloakClient) AddClientRolesToUser(ctx context.Context, userID, clientID string, roleNames []string) error {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return fmt.Errorf(ErrTokenRefreshFailed, err)
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return fmt.Errorf(ErrFailedToGetClientWrapper, err)
	}
	clientUUID := client.ID

	var roles []Role
	for _, roleName := range roleNames {
		role, err := ka.getClientRole(ctx, clientUUID, roleName)
		if err != nil {
			return fmt.Errorf(ErrFailedToGetClientRoleWrapper, roleName, err)
		}
		roles = append(roles, *role)
	}

	jsonBody, err := json.Marshal(roles)
	if err != nil {
		return fmt.Errorf(ErrFailedToMarshalClientRoles, err)
	}

	addURL := fmt.Sprintf("%s/%s/role-mappings/clients/%s", ka.baseURL, userID, clientUUID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addURL, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf(ErrFailedToCreateAddClientRolesRequest, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return fmt.Errorf(ErrFailedToExecuteAddClientRoles, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf(ErrFailedToAddClientRoles, resp.StatusCode, body)
	}
	return nil
}

func (ka *KeycloakClient) TriggerPasswordResetEmail(ctx context.Context, userID string) error {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return fmt.Errorf(ErrTokenRefreshFailed, err)
	}
	if userID == emptyString {
		return fmt.Errorf(ErrUserIDRequired)
	}
	resetURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/reset-password-email", ka.config.URL, ka.config.Realm, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, resetURL, nil)
	if err != nil {
		return fmt.Errorf(ErrFailedToCreateResetPasswordEmailRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)
	resp, err := ka.client.Do(req)
	if err != nil {
		return fmt.Errorf(ErrFailedToExecuteResetPasswordEmailRequest, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf(ErrFailedToTriggerPasswordResetEmail, resp.StatusCode, body)
	}
	return nil
}

func (ka *KeycloakClient) GetUserIDByUsername(ctx context.Context, username string, exact bool) (string, error) {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return emptyString, fmt.Errorf(ErrTokenRefreshFailed, err)
	}
	if username == emptyString {
		return emptyString, fmt.Errorf(ErrUsernameRequired)
	}
	searchURL := ka.baseURL
	params := url.Values{}
	params.Add("username", username)
	if exact {
		params.Add("exact", "true")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL+"?"+params.Encode(), nil)
	if err != nil {
		return emptyString, fmt.Errorf(ErrFailedToCreateGetUserRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)
	resp, err := ka.client.Do(req)
	if err != nil {
		return emptyString, fmt.Errorf(ErrFailedToExecuteGetUser, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return emptyString, fmt.Errorf(ErrFailedToGetUser, resp.StatusCode, body)
	}
	var users []User
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return emptyString, fmt.Errorf(ErrFailedToDecodeUser, err)
	}
	if len(users) == 0 {
		return emptyString, fmt.Errorf(ErrNoUserFound, username)
	}
	if len(users) > 1 {
		return emptyString, fmt.Errorf(ErrMultipleUsersFound, username)
	}
	return users[0].ID, nil
}
