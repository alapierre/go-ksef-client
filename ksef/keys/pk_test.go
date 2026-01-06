package keys

import (
	"testing"

	"github.com/alapierre/go-ksef-client/ksef/util"
)

func TestRead(t *testing.T) {

	pass := util.GetEnvOrFailed("KSEF_CERT_PASS")

	_, err := LoadEncryptedPKCS8SignerFromFile("../../test/test-sign.key", []byte(pass))
	if err != nil {
		t.Fatalf("LoadEncryptedPKCS8PrivateKeyFromFile failed: %v", err)
	}
}
