package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/alapierre/go-ksef-client/ksef"
	"github.com/alapierre/go-ksef-client/ksef/cipher"
	"github.com/alapierre/go-ksef-client/ksef/util"
)

func main() {

	nip := util.GetEnvOrFailed("KSEF_NIP")
	token := util.GetEnvOrFailed("KSEF_TOKEN")

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	env := ksef.Test

	client, err := ksef.NewAuthFacade(env, httpClient)

	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	challenge, err := client.GetChallenge(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println(challenge)

	encryptor, err := cipher.NewEncryptionService(env, httpClient)
	if err != nil {
		panic(err)
	}

	encryptedToken, err := encryptor.EncryptKsefToken(ctx, token, challenge.Timestamp)
	if err != nil {
		panic(err)
	}

	initResp, err := client.AuthWithToken(ctx, challenge.Challenge, ksef.Nip(nip), encryptedToken)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tokens, err := client.AuthWaitAndRedeem(ctx, initResp, 1*time.Second)

	if err != nil {
		panic(err)
	}

	fmt.Println(tokens.AccessToken.Token)
	fmt.Println(tokens.RefreshToken.Token)

	refreshToken, err := client.RefreshToken(ctx, tokens.RefreshToken.Token)
	if err != nil {
		return
	}

	fmt.Println(refreshToken.GetToken())
	fmt.Println("Refreshed")

}
