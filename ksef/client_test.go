package ksef

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
	"github.com/alapierre/go-ksef-client/ksef/util"
	"github.com/sirupsen/logrus"
)

func TestClient_OpenInteractiveSession(t *testing.T) {

	logrus.SetLevel(logrus.DebugLevel)

	nip := util.GetEnvOrFailed("KSEF_NIP")
	token := util.GetEnvOrFailed("KSEF_TOKEN")

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	env := Test

	authFacade, err := NewFacade(env, httpClient)

	if err != nil {
		t.Fatal(err)
	}

	encryptor, err := NewEncryptionService(env, httpClient)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	ctx = Context(ctx, nip)

	provider := NewTokenProvider(authFacade, func(ctx context.Context) (*api.AuthenticationTokensResponse, error) {
		return WithKsefToken(ctx, authFacade, encryptor, token)
	})

	client, err := New(env, httpClient, provider)

	form := api.FormCode{
		SystemCode:    "FA (3)",
		SchemaVersion: "1-0E",
		Value:         "FA",
	}

	key, err := GenerateRandom256BitsKey()
	iv, err := GenerateRandom16BytesIv()
	encryptedKey, err := encryptor.EncryptSymmetricKey(ctx, key)

	enc := api.EncryptionInfo{
		EncryptedSymmetricKey: encryptedKey,
		InitializationVector:  iv,
	}

	session, err := client.OpenInteractiveSession(ctx, form, enc)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(session)

}
