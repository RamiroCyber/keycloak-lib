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
- **Admin API Support**: User create/get/delete with attributes, passwords, and verification; add client-specific roles to users.
- **Token Management**: Client credentials grant, caching, and auto-refresh based on `expires_in`.
- **Thread-Safety**: Mutex-protected token operations for concurrent use.
- **Customization**: Env var-driven config for realms/clients; validation on init.
- **Minimal Dependencies**: Standard lib + `go-oidc`; no heavy wrappers.
- **Error Handling**: Detailed errors with HTTP status/body.

## Installation
Add to your `go.mod`:

```bash
go get github.com/RamiroCyber/keycloak-lib@latest
```

Run `go mod tidy`. Requires Go 1.24+.

## Configuration
Use `NewConfig` which validates inputs and returns `(*Config, error)`.

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

config, err := keycloaklib.NewConfig(
	os.Getenv("KEYCLOAK_URL"),
	os.Getenv("KEYCLOAK_REALM"),
	os.Getenv("KEYCLOAK_CLIENT_ID"),
	os.Getenv("KEYCLOAK_CLIENT_SECRET"),
    os.Getenv("KEYCLOAK_PUBLIC_CLIENT_ID"),

)
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
```go
params := keycloaklib.UserCreateParams{
	// Fields...
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
