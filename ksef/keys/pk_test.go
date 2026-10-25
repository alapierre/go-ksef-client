package keys

import (
	"os"
	"testing"
)

func TestRead(t *testing.T) {

	pass := os.Getenv("KSEF_CERT_PASS")
	if pass == "" {
		t.Skip("KSEF_CERT_PASS not set – skipping certificate test")
	}

	_, err := LoadEncryptedPKCS8SignerFromFile("../../test/test-sign.key", []byte(pass))
	if err != nil {
		t.Fatalf("LoadEncryptedPKCS8PrivateKeyFromFile failed: %v", err)
	}
}
