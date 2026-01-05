package rsa

import (
	"testing"

	"github.com/alapierre/go-ksef-client/ksef/util"
)

func TestRead(t *testing.T) {

	pass := util.GetEnvOrFailed("KSEF_CERT_PASS")

	_, err := LoadEncryptedPKCS8PrivateKeyFromFile("../../test/test-sign.key", []byte(pass))
	if err != nil {
		t.Fatalf("LoadEncryptedPKCS8PrivateKeyFromFile failed: %v", err)
	}
}
