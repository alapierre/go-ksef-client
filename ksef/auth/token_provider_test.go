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
	"github.com/sirupsen/logrus"
)

func TestGetToken(t *testing.T) {

	logrus.SetLevel(logrus.DebugLevel)

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
	ctx = ksef.Context(ctx, nip)

	provider := NewTokenProvider(authFacade, func(ctx context.Context) (*api.AuthenticationTokensResponse, error) {
		return initTokens(ctx, authFacade, encryptor, token)
	})

	b, err := provider.Bearer(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(b.Token)
}

func initTokens(ctx context.Context, authFacade *Facade, encryptor *cipher.EncryptionService, token string) (*api.AuthenticationTokensResponse, error) {

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
