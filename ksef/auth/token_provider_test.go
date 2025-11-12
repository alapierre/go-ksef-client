package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef"
	"github.com/alapierre/go-ksef-client/ksef/api"
	"github.com/alapierre/go-ksef-client/ksef/cipher"
	"github.com/alapierre/go-ksef-client/ksef/util"
)

func TestGetToken(t *testing.T) {

	nip := util.GetEnvOrFailed("KSEF_NIP")
	token := util.GetEnvOrFailed("KSEF_TOKEN")

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	env := ksef.Test

	authFacade, err := NewFacade(env, httpClient)

	if err != nil {
		t.Fatal(err)
	}

	encryptor, err := cipher.NewEncryptionService(env, httpClient)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	provider, err := NewTokenProvider(ctx, authFacade, func(ctx context.Context) (*api.AuthenticationTokensResponse, error) {
		return initTokens(authFacade, encryptor, token, nip)
	})
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(provider.accessToken)
}

func initTokens(authFacade *Facade, encryptor *cipher.EncryptionService, token string, nip string) (*api.AuthenticationTokensResponse, error) {

	ctx := context.Background()
	challenge, err := authFacade.GetChallenge(ctx)
	if err != nil {
		return nil, err
	}

	encryptedToken, err := encryptor.EncryptKsefToken(ctx, token, challenge.Timestamp)
	if err != nil {
		return nil, err
	}

	initResp, err := authFacade.AuthWithToken(ctx, challenge.Challenge, ksef.Nip(nip), encryptedToken)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	return authFacade.AuthWaitAndRedeem(ctx, initResp, 1*time.Second)
}
