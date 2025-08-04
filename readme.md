# Keycloak Go Library

![Go Version](https://img.shields.io/badge/Go-1.23%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen) <!-- Add actual badges if available -->
![GoDoc](https://pkg.go.dev/badge/github.com/RamiroCyber/keycloak-lib?status.svg)

A lightweight Go library for integrating with Keycloak. It supports Keycloak Admin REST API operations (e.g., user management) using direct HTTP calls. Built with `net/http` and `encoding/json` for admin interactions, and `golang.org/x/oauth2` for token handling, it focuses on security, thread-safety, and ease of use.

This library is suitable for backend services, APIs, or CLI tools requiring Keycloak integration. It handles token fetching via client credentials grant, automatic refresh using `expires_in`, and caching.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Initializing the Library](#initializing-the-library)
  - [Admin Operations](#admin-operations)
- [Full Example: Web App Integration](#full-example-web-app-integration)
- [Best Practices](#best-practices)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Features
- **Admin API Support**: User create/get/delete with attributes, passwords, verification, and required actions; add client-specific roles to users; trigger password reset emails; get user ID by username.
- **Token Management**: Client credentials grant, caching, and auto-refresh based on `expires_in`.
- **User Login**: Supports password grant for obtaining OAuth2 tokens.
- **Thread-Safety**: Mutex-protected token operations for concurrent use.
- **Customization**: Env var-driven config for realms/clients; validation on init; support for error messages in English or Portuguese.
- **Minimal Dependencies**: Standard lib + `golang.org/x/oauth2`; no heavy wrappers.
- **Error Handling**: Detailed errors with HTTP status/body; internationalized messages (en/pt).
- **Builder Pattern**: Fluent builders for configuration and user creation parameters for improved readability and flexibility.

## Installation
Add to your `go.mod`:

```bash
go get github.com/RamiroCyber/keycloak-lib@latest
```

Run `go mod tidy`. Requires Go 1.23+.

## Configuration
Use the `ConfigBuilder` to create and validate the configuration in a fluent manner. You can also specify the language for error messages ("en" for English or "pt" for Portuguese; defaults to "en").

### Environment Variables
Set in your project:

- `KEYCLOAK_URL`: Server URL (required).
- `KEYCLOAK_REALM`: Realm (required).
- `KEYCLOAK_CLIENT_ID`: Client ID (required).
- `KEYCLOAK_CLIENT_SECRET`: Secret (required).
- `KEYCLOAK_PUBLIC_CLIENT_ID`: Public Client (optional).

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
    WithLanguage("pt"). // Optional: "pt" for Portuguese errors, defaults to "en"
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

admin, err := keycloaklib.NewKeycloakClient(ctx, config)
if err != nil {
    log.Fatal(err)
}
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
if err != nil {
    // Handle error
}
```

#### Get User by ID
```go
user, err := admin.GetUserByID(ctx, "user-id")
if err != nil {
    // Handle error
}
```

#### Get User ID by Username
```go
userID, err := admin.GetUserIDByUsername(ctx, "username", true) // true for exact match
if err != nil {
    // Handle error
}
```

#### Delete User
```go
err := admin.DeleteUser(ctx, "user-id")
if err != nil {
    // Handle error
}
```

#### Add Client Roles to User
```go
err := admin.AddClientRolesToUser(ctx, "user-id", "client-id", []string{"role1", "role2"})
if err != nil {
    // Handle error
}
```

#### Trigger Password Reset Email
```go
err := admin.TriggerPasswordResetEmail(ctx, "user-id")
if err != nil {
    // Handle error
}
```

#### User Login (Password Grant)
```go
token, err := admin.Login(ctx, "username", "password", []string{"scope1", "scope2"})
if err != nil {
    // Handle error
}
// Use token.AccessToken, etc.
```

## Full Example: Web App Integration
For a complete example integrating this library into a web app (e.g., with Gin or Echo), see the examples directory in the repository (coming soon) or adapt the usage snippets above.

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