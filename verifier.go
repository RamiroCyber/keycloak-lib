package keycloaklib

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

type KeycloakVerifier struct {
	verifier *oidc.IDTokenVerifier
}

func NewKeycloakVerifier(ctx context.Context, config *Config) (*KeycloakVerifier, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	provider, err := config.Provider(ctx)
	if err != nil {
		return nil, err
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})
	return &KeycloakVerifier{verifier: verifier}, nil
}

func (kv *KeycloakVerifier) ValidateToken(ctx context.Context, rawToken string) (*oidc.IDToken, error) {
	if rawToken == "" {
		return nil, errors.New("token is empty")
	}
	return kv.verifier.Verify(ctx, rawToken)
}
