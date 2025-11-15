package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/alapierre/go-ksef-client/ksef"
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
	authFacade, err := ksef.NewAuthFacade(env, httpClient)
	if err != nil {
		panic(err)
	}

	encryptor, err := ksef.NewEncryptionService(env, httpClient)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	ctx = ksef.Context(ctx, nip)
	tokens, err := ksef.WithKsefToken(ctx, authFacade, encryptor, token)

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
