# Keycloak Go Library

![Go Version](https://img.shields.io/badge/Go-1.24%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen) <!-- Add actual badges if available -->
![GoDoc](https://pkg.go.dev/badge/github.com/RamiroCyber/keycloak-lib?status.svg)

A lightweight Go library for integrating with Keycloak. It supports OIDC token validation and Keycloak Admin REST API operations (e.g., user management) using direct HTTP calls. Built with `net/http` and `encoding/json` for admin interactions, and `github.com/coreos/go-oidc/v3` for OIDC, it focuses on security, thread-safety, and ease of use.

This library is suitable for backend services, APIs, or CLI tools requiring Keycloak integration. It handles token fetching via client credentials grant, automatic refresh using `expires_in`, and caching.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Initializing the Library](#initializing-the-library)
  - [OIDC Token Verification](#oidc-token-verification)
  - [Admin Operations](#admin-operations)
- [Full Example: Web App Integration](#full-example-web-app-integration)
- [Best Practices](#best-practices)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Features
- **OIDC Token Validation**: Offline JWT validation against Keycloak's JWKS.
- **Admin API Support**: User create/get/delete with attributes, passwords, verification, and required actions; add client-specific roles to users.
- **Token Management**: Client credentials grant, caching, and auto-refresh based on `expires_in`.
- **Thread-Safety**: Mutex-protected token operations for concurrent use.
- **Customization**: Env var-driven config for realms/clients; validation on init.
- **Minimal Dependencies**: Standard lib + `go-oidc`; no heavy wrappers.
- **Error Handling**: Detailed errors with HTTP status/body.
- **Builder Pattern**: Fluent builders for configuration and user creation parameters for improved readability and flexibility.

## Installation
Add to your `go.mod`:

```bash
go get github.com/RamiroCyber/keycloak-lib@latest
```

Run `go mod tidy`. Requires Go 1.24+.

## Configuration
Use the `ConfigBuilder` to create and validate the configuration in a fluent manner.

### Environment Variables
Set in your project:

- `KEYCLOAK_URL`: Server URL (required).
- `KEYCLOAK_REALM`: Realm (required).
- `KEYCLOAK_CLIENT_ID`: Client ID (required).
- `KEYCLOAK_CLIENT_SECRET`: Secret (required).
- `KEYCLOAK_PUBLIC_CLIENT_ID`: Public Client.

### Creating Config
```go
import (
	"os"
	"github.com/RamiroCyber/keycloak-lib"
	"github.com/joho/godotenv" // Optional
)

_ = godotenv.Load()

config, err := keycloaklib.NewConfigBuilder().
	WithURL(os.Getenv("KEYCLOAK_URL")).
	WithRealm(os.Getenv("KEYCLOAK_REALM")).
	WithClientID(os.Getenv("KEYCLOAK_CLIENT_ID")).
	WithClientSecret(os.Getenv("KEYCLOAK_CLIENT_SECRET")).
	WithPublicClientID(os.Getenv("KEYCLOAK_PUBLIC_CLIENT_ID")).
	Build()
if err != nil {
	log.Fatal(err)
}
```

## Usage

### Initializing the Library
Init once and reuse.

```go
ctx := context.Background()

verifier, err := keycloaklib.NewKeycloakVerifier(ctx, config)
if err != nil {
	log.Fatal(err)
}

admin, err := keycloaklib.NewKeycloakClient(ctx, config)
if err != nil {
	log.Fatal(err)
}
```

### OIDC Token Verification
```go
idToken, err := verifier.ValidateToken(ctx, "jwt-token")
if err != nil {
	// Handle
}
var claims map[string]interface{}
idToken.Claims(&claims)
```

### Admin Operations
#### Create User
Use the `UserCreateParamsBuilder` for fluent parameter construction, including optional required actions like "UPDATE_PASSWORD" or "VERIFY_EMAIL".

```go
params, err := keycloaklib.NewUserCreateParamsBuilder().
	WithUsername("username").
	WithEmail("email@example.com").
	WithFirstName("First").
	WithLastName("Last").
	WithAttributes(map[string][]string{"attribute1": {"value1"}}).
	AddCredential(keycloaklib.Credential{Type: "password", Value: "password", Temporary: false}).
	WithRequiredActions([]string{"UPDATE_PASSWORD", "VERIFY_EMAIL"}).
	Build()
if err != nil {
	// Handle error
}
userID, err := admin.CreateUser(ctx, params)
```

#### Get User
```go
user, err := admin.GetUserByID(ctx, "id")
```

#### Delete User
```go
err := admin.DeleteUser(ctx, "id")
```

#### Add Client Roles to User
```go
err := admin.AddClientRolesToUser(ctx, "userID", "clientID", []string{"role1", "role2"})
if err != nil {
	// Handle
}
```

## Full Example: Web App Integration
See previous messages or repo examples.

## Best Practices
- Init once, inject dependencies.
- Use env vars/secrets managers.
- Monitor token logs.

## Security Considerations
- Secure secrets.
- Use HTTPS.
- Minimal permissions.

## Testing
<!-- Add testing details if available -->

## Contributing
<!-- Add contributing guidelines -->

## License
MIT License

## Acknowledgments
<!-- Add acknowledgments if any -->