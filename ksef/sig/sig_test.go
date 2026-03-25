package sig

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef"
	"github.com/alapierre/godss/keystore"
	"github.com/stretchr/testify/require"
)

func TestWithXades(t *testing.T) {

	privateKeyPath := "../../test_data/auth-cert.key"
	certificatePath := "../../test_data/auth-cert.crt"

	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Skipf("Pomijanie testu: brak pliku %s", privateKeyPath)
	}

	pin := os.Getenv("SIG_PASS")
	if pin == "" {
		t.Skip("Pomijanie testu: brak hasła do klucza prywatnego")
	}

	nip := os.Getenv("SIG_NIP")
	if nip == "" {
		t.Skip("Pomijanie testu: brak NIP")
	}

	signer, err := keystore.NewX509KeyStoreSigner(privateKeyPath, certificatePath, keystore.WithPrivateKeyPassword(pin))
	require.NoError(t, err)

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	env := ksef.Test

	authFacade, err := ksef.NewAuthFacade(env, httpClient)
	ctx := ksef.ContextWithEnv(context.Background(), nip, env)

	res, err := WithXades(ctx, authFacade, signer)
	require.NoError(t, err)

	t.Log(res.ReferenceNumber)

	require.NotNil(t, res)
	require.NotEmpty(t, res.Tokens.AccessToken)
	require.NotEmpty(t, res.Tokens.RefreshToken)

}
