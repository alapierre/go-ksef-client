package auth

import (
	"context"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

type TokenRefresher interface {
	RefreshToken(ctx context.Context, refreshToken string) (api.TokenInfo, error)
}
