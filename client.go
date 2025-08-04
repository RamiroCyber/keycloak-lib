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

func getClientToken(ctx context.Context, config *Config, lang string) (*tokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", config.URL, config.Realm)
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, makeError(lang, ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, makeError(lang, ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, makeError(lang, ErrFailedToReadResponse, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, makeError(lang, ErrFailedToGetToken, resp.StatusCode, body)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, makeError(lang, ErrFailedToParseToken, err)
	}
	if tok.AccessToken == emptyString {
		return nil, makeError(lang, ErrNoAccessToken)
	}
	return &tok, nil
}

func (ka *KeycloakClient) refreshAdminToken(ctx context.Context) error {
	if ka.refreshToken == emptyString {
		return ka.errorf(ErrNoRefreshToken)
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", ka.config.URL, ka.config.Realm)
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", ka.config.ClientID)
	data.Set("client_secret", ka.config.ClientSecret)
	data.Set("refresh_token", ka.refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return ka.errorf(ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ka.client.Do(req)
	if err != nil {
		return ka.errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ka.errorf(ErrFailedToReadResponse, err)
	}
	if resp.StatusCode != http.StatusOK {
		return ka.errorf(ErrFailedToRefreshToken, resp.StatusCode, body)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return ka.errorf(ErrFailedToParseToken, err)
	}
	if tok.AccessToken == emptyString {
		return ka.errorf(ErrNoAccessTokenInRefresh)
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

	tok, err := getClientToken(ctx, ka.config, ka.language)
	if err != nil {
		return ka.errorf(ErrTokenRefreshFailed, err)
	}
	ka.accessToken = tok.AccessToken
	ka.refreshToken = tok.RefreshToken
	ka.expiry = time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - 30*time.Second)
	return nil
}

func NewKeycloakClient(ctx context.Context, config *Config) (*KeycloakClient, error) {
	if config == nil {
		return nil, makeError("en", ErrConfigRequired)
	}
	lang := config.Language
	if lang != "pt" {
		lang = "en"
	}
	if config.ClientID == emptyString || config.ClientSecret == emptyString {
		return nil, makeError(lang, ErrClientIDAndSecretRequired)
	}

	tok, err := getClientToken(ctx, config, lang)
	if err != nil {
		return nil, err
	}

	expiry := time.Now().Add(time.Duration(tok.ExpiresIn)*time.Second - 30*time.Second)

	ka := &KeycloakClient{
		client:       http.DefaultClient,
		accessToken:  tok.AccessToken,
		refreshToken: tok.RefreshToken,
		expiry:       expiry,
		config:       config,
		language:     lang,
		baseURL:      fmt.Sprintf("%s/admin/realms/%s/users", config.URL, config.Realm),
	}
	return ka, nil
}

func (ka *KeycloakClient) CreateUser(ctx context.Context, params UserCreateParams) (string, error) {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return emptyString, ka.errorf(ErrTokenRefreshFailed, err)
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
		return emptyString, ka.errorf(ErrFailedToMarshalUser, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ka.baseURL, bytes.NewReader(jsonBody))
	if err != nil {
		return emptyString, ka.errorf(ErrFailedToCreateUserRequest, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return emptyString, ka.errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return emptyString, ka.errorf(ErrFailedToCreateUser, resp.StatusCode, body)
	}

	location := resp.Header.Get("Location")
	if location == emptyString {
		return emptyString, ka.errorf(ErrNoLocationHeader)
	}
	parts := strings.Split(location, "/")
	if len(parts) < 2 {
		return emptyString, ka.errorf(ErrInvalidLocationHeader)
	}
	userID := parts[len(parts)-1]

	return userID, nil
}

func (ka *KeycloakClient) GetUserByID(ctx context.Context, userID string) (*User, error) {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return nil, ka.errorf(ErrTokenRefreshFailed, err)
	}

	url := fmt.Sprintf("%s/%s", ka.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, ka.errorf(ErrFailedToGetUserRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return nil, ka.errorf(ErrFailedToExecuteGetUser, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, ka.errorf(ErrFailedToGetUser, resp.StatusCode, body)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, ka.errorf(ErrFailedToDecodeUser, err)
	}
	return &user, nil
}

func (ka *KeycloakClient) DeleteUser(ctx context.Context, userID string) error {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return ka.errorf(ErrTokenRefreshFailed, err)
	}

	url := fmt.Sprintf("%s/%s", ka.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return ka.errorf(ErrFailedToDeleteUserRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return ka.errorf(ErrFailedToExecuteDeleteUser, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return ka.errorf(ErrFailedToDeleteUser, resp.StatusCode, body)
	}
	return nil
}

func (ka *KeycloakClient) Login(ctx context.Context, username, password string, scopes []string) (*oauth2.Token, error) {
	if username == emptyString || password == emptyString {
		return nil, ka.errorf(ErrUsernamePasswordRequired)
	}
	clientID := ka.config.ClientID
	if ka.config.PublicClientID != emptyString {
		clientID = ka.config.PublicClientID
	}
	if clientID == emptyString {
		return nil, ka.errorf(ErrClientIDRequired)
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
		return nil, ka.errorf(ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ka.errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ka.errorf(ErrFailedToReadResponse, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ka.errorf(ErrFailedToObtainLoginToken, resp.StatusCode, body)
	}

	var token oauth2.Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, ka.errorf(ErrFailedToParseToken, err)
	}

	if token.AccessToken == emptyString {
		return nil, ka.errorf(ErrNoAccessToken)
	}

	return &token, nil
}

func (ka *KeycloakClient) getClientByClientID(ctx context.Context, clientID string) (*Client, error) {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return nil, ka.errorf(ErrTokenRefreshFailed, err)
	}

	clientURL := fmt.Sprintf("%s/admin/realms/%s/clients?clientId=%s", ka.config.URL, ka.config.Realm, url.QueryEscape(clientID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientURL, nil)
	if err != nil {
		return nil, ka.errorf(ErrFailedToCreateGetClientRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return nil, ka.errorf(ErrFailedToExecuteGetClient, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, ka.errorf(ErrFailedToGetClient, resp.StatusCode, body)
	}

	var clients []Client
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, ka.errorf(ErrFailedToDecodeClients, err)
	}

	if len(clients) == 0 {
		return nil, ka.errorf(ErrNoClientFound, clientID)
	}

	return &clients[0], nil
}

func (ka *KeycloakClient) getClientRole(ctx context.Context, clientUUID, roleName string) (*Role, error) {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return nil, ka.errorf(ErrTokenRefreshFailed, err)
	}

	roleURL := fmt.Sprintf("%s/admin/realms/%s/clients/%s/roles/%s", ka.config.URL, ka.config.Realm, clientUUID, url.PathEscape(roleName))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, roleURL, nil)
	if err != nil {
		return nil, ka.errorf(ErrFailedToCreateGetClientRoleRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return nil, ka.errorf(ErrFailedToExecuteGetClientRole, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, ka.errorf(ErrFailedToGetClientRole, resp.StatusCode, body)
	}

	var role Role
	if err := json.NewDecoder(resp.Body).Decode(&role); err != nil {
		return nil, ka.errorf(ErrFailedToDecodeClientRole, err)
	}
	return &role, nil
}

func (ka *KeycloakClient) AddClientRolesToUser(ctx context.Context, userID, clientID string, roleNames []string) error {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return ka.errorf(ErrTokenRefreshFailed, err)
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return ka.errorf(ErrFailedToGetClientWrapper, err)
	}
	clientUUID := client.ID

	var roles []Role
	for _, roleName := range roleNames {
		role, err := ka.getClientRole(ctx, clientUUID, roleName)
		if err != nil {
			return ka.errorf(ErrFailedToGetClientRoleWrapper, roleName, err)
		}
		roles = append(roles, *role)
	}

	jsonBody, err := json.Marshal(roles)
	if err != nil {
		return ka.errorf(ErrFailedToMarshalClientRoles, err)
	}

	addURL := fmt.Sprintf("%s/%s/role-mappings/clients/%s", ka.baseURL, userID, clientUUID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addURL, bytes.NewReader(jsonBody))
	if err != nil {
		return ka.errorf(ErrFailedToCreateAddClientRolesRequest, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)

	resp, err := ka.client.Do(req)
	if err != nil {
		return ka.errorf(ErrFailedToExecuteAddClientRoles, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return ka.errorf(ErrFailedToAddClientRoles, resp.StatusCode, body)
	}
	return nil
}

func (ka *KeycloakClient) TriggerPasswordResetEmail(ctx context.Context, userID string) error {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return ka.errorf(ErrTokenRefreshFailed, err)
	}
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	resetURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/reset-password-email", ka.config.URL, ka.config.Realm, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, resetURL, nil)
	if err != nil {
		return ka.errorf(ErrFailedToCreateResetPasswordEmailRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)
	resp, err := ka.client.Do(req)
	if err != nil {
		return ka.errorf(ErrFailedToExecuteResetPasswordEmailRequest, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return ka.errorf(ErrFailedToTriggerPasswordResetEmail, resp.StatusCode, body)
	}
	return nil
}

func (ka *KeycloakClient) GetUserIDByUsername(ctx context.Context, username string, exact bool) (string, error) {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return emptyString, ka.errorf(ErrTokenRefreshFailed, err)
	}
	if username == emptyString {
		return emptyString, ka.errorf(ErrUsernameRequired)
	}
	searchURL := ka.baseURL
	params := url.Values{}
	params.Add("username", username)
	if exact {
		params.Add("exact", "true")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL+"?"+params.Encode(), nil)
	if err != nil {
		return emptyString, ka.errorf(ErrFailedToCreateGetUserRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)
	resp, err := ka.client.Do(req)
	if err != nil {
		return emptyString, ka.errorf(ErrFailedToExecuteGetUser, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return emptyString, ka.errorf(ErrFailedToGetUser, resp.StatusCode, body)
	}
	var users []User
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return emptyString, ka.errorf(ErrFailedToDecodeUser, err)
	}
	if len(users) == 0 {
		return emptyString, ka.errorf(ErrNoUserFound, username)
	}
	if len(users) > 1 {
		return emptyString, ka.errorf(ErrMultipleUsersFound, username)
	}
	return users[0].ID, nil
}
