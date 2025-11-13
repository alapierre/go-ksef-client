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

func TestGetToken(t *testing.T) {

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

	b, err := provider.Bearer(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(b.Token)
}
