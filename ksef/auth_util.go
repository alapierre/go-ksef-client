package ksef

import (
	"context"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

func WithKsefToken(ctx context.Context, authFacade *Facade, encryptor *EncryptionService, token string) (*api.AuthenticationTokensResponse, error) {

	challenge, err := authFacade.GetChallenge(ctx)
	if err != nil {
		return nil, err
	}

	encryptedToken, err := encryptor.EncryptKsefToken(ctx, token, challenge.Timestamp)
	if err != nil {
		return nil, err
	}

	initResp, err := authFacade.AuthWithToken(ctx, challenge.Challenge, encryptedToken)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	return authFacade.AuthWaitAndRedeem(ctx, initResp, 1*time.Second)
}
