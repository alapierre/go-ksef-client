package ksef

import (
	"context"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

func WithKsefToken(ctx context.Context, authFacade *AuthFacade, encryptor *EncryptionService, token string) (*api.AuthenticationTokensResponse, error) {

	r, err := WithKsefTokenResult(ctx, authFacade, encryptor, token)
	if err != nil {
		return nil, err
	}
	return r.Tokens, nil
}

type AuthResult struct {
	ReferenceNumber string
	Tokens          *api.AuthenticationTokensResponse
}

func WithKsefTokenResult(ctx context.Context, authFacade *AuthFacade, encryptor *EncryptionService, token string) (*AuthResult, error) {
	challenge, err := authFacade.GetChallenge(ctx)
	if err != nil {
		return nil, err
	}

	encryptedToken, err := encryptor.EncryptKsefTokenWithKeyID(ctx, token, challenge.Timestamp)
	if err != nil {
		return nil, err
	}

	initResp, err := authFacade.AuthWithToken(ctx, challenge.Challenge, encryptedToken.Data, encryptedToken.PublicKeyID)
	if IsPublicKeyRejectedError(err) {
		logger.Info("Public key rejected, refreshing encryption key")
		if refreshErr := encryptor.ForceRefresh(ctx); refreshErr != nil {
			return nil, refreshErr
		}
		encryptedToken, err = encryptor.EncryptKsefTokenWithKeyID(ctx, token, challenge.Timestamp)
		if err != nil {
			return nil, err
		}
		logger.Infof("trying to auth in KSeF again with newly encrypted token")
		initResp, err = authFacade.AuthWithToken(ctx, challenge.Challenge, encryptedToken.Data, encryptedToken.PublicKeyID)
	}
	if err != nil {
		return nil, err
	}

	ctx = ContextWithAuthReference(ctx, string(initResp.ReferenceNumber))
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	res, err := authFacade.AuthWaitAndRedeem(ctx, initResp, 1*time.Second)
	if err != nil {
		return nil, err
	}

	return &AuthResult{ReferenceNumber: string(initResp.ReferenceNumber), Tokens: res}, nil
}
