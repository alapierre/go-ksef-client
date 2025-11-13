package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/alapierre/go-ksef-client/ksef"
	"github.com/alapierre/go-ksef-client/ksef/api"
	"github.com/alapierre/go-ksef-client/ksef/auth"
	"github.com/alapierre/go-ksef-client/ksef/cipher"
	"github.com/alapierre/go-ksef-client/ksef/util"
	"github.com/sirupsen/logrus"
)

func main() {

	logrus.SetLevel(logrus.DebugLevel)

	nip := util.GetEnvOrFailed("KSEF_NIP")
	token := util.GetEnvOrFailed("KSEF_TOKEN")

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	env := ksef.Test
	authFacade, err := auth.NewFacade(env, httpClient)
	if err != nil {
		panic(err)
	}

	encryptor, err := cipher.NewEncryptionService(env, httpClient)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	ctx = ksef.Context(ctx, nip)
	tokens, err := initTokens(ctx, authFacade, encryptor, token)

	if err != nil {
		panic(err)
	}

	fmt.Println(tokens.AccessToken.Token)
	fmt.Println(tokens.RefreshToken.Token)

	refreshToken, err := authFacade.RefreshToken(ctx, tokens.RefreshToken.Token)
	if err != nil {
		panic(err)
	}

	fmt.Println(refreshToken.GetToken())
	fmt.Println("Refreshed")
}

func initTokens(ctx context.Context, authFacade *auth.Facade, encryptor *cipher.EncryptionService, token string) (*api.AuthenticationTokensResponse, error) {

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
