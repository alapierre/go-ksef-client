package ksef

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/aes"
	"github.com/alapierre/go-ksef-client/ksef/api"
	"github.com/alapierre/go-ksef-client/ksef/util"
	"github.com/sirupsen/logrus"
)

func TestClient_OpenInteractiveSession(t *testing.T) {

	logrus.SetLevel(logrus.DebugLevel)

	nip := util.GetEnvOrFailed("KSEF_NIP")
	token := util.GetEnvOrFailed("KSEF_TOKEN")
	buer := util.GetEnvOrFailed("KSEF_BUYER_NIP")

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

	client, err := NewClient(env, httpClient, provider)

	form := api.FormCode{
		SystemCode:    "FA (3)",
		SchemaVersion: "1-0E",
		Value:         "FA",
	}

	key, err := aes.GenerateRandom256BitsKey()
	iv, err := aes.GenerateRandom16BytesIv()
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

	invoice, err := util.ReplacePlaceholdersInXML("../invoice_fa_3_type.xml", map[string]any{
		"NIP":        nip,
		"ISSUE_DATE": time.Now(),
		"BUYER_NIP":  buer,
	})
	if err != nil {
		t.Fatal(err)
	}

	ir, err := client.SendInvoice(ctx, string(session.ReferenceNumber), api.OptBool{}, invoice, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(ir)
}
