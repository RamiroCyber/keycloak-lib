package keycloaklib

const (
	emptyString = ""
)
const (
	ErrConfigRequired            = "config is required"
	ErrClientIDAndSecretRequired = "client_id and client_secret are required for admin operations"
	ErrNoAccessToken             = "no access token in response"
	ErrNoRefreshToken            = "no refresh token available"
	ErrNoAccessTokenInRefresh    = "no access token in refresh response"
	ErrTokenRefreshFailed        = "token refresh failed: %w"
	ErrFailedToCreateRequest     = "failed to create request: %w"
	ErrFailedToExecuteRequest    = "failed to execute request: %w"
	ErrFailedToReadResponse      = "failed to read response: %w"
	ErrFailedToGetToken          = "failed to get token: %d %s"
	ErrFailedToRefreshToken      = "failed to refresh token: %d %s"
	ErrFailedToParseToken        = "failed to parse token response: %w"
	ErrFailedToMarshalUser       = "failed to marshal user data: %w"
	ErrFailedToCreateUserRequest = "failed to create user request: %w"
	ErrFailedToCreateUser        = "failed to create user: %d %s"
	ErrNoLocationHeader          = "no Location header in response"
	ErrInvalidLocationHeader     = "invalid Location header"
	ErrFailedToGetUserRequest    = "failed to create get user request: %w"
	ErrFailedToExecuteGetUser    = "failed to execute get user request: %w"
	ErrFailedToGetUser           = "failed to get user: %d %s"
	ErrFailedToDecodeUser        = "failed to decode user response: %w"
	ErrFailedToDeleteUserRequest = "failed to create delete user request: %w"
	ErrFailedToExecuteDeleteUser = "failed to execute delete user request: %w"
	ErrFailedToDeleteUser        = "failed to delete user: %d %s"
	ErrUsernamePasswordRequired  = "username and password are required"
	ErrClientIDRequired          = "client_id or other_client_id is required"
	ErrFailedToObtainLoginToken  = "failed to obtain login token: status %d, body: %s"
)
