package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/youmark/pkcs8"
)

// LoadEncryptedPKCS8SignerFromFile ładuje klucz z PEM i zwraca crypto.Signer.
func LoadEncryptedPKCS8SignerFromFile(path string, password []byte) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	return LoadEncryptedPKCS8SignerFromPEM(b, password)
}

// LoadEncryptedPKCS8SignerFromPEM ładuje pierwszy znaleziony blok ENCRYPTED PRIVATE KEY.
func LoadEncryptedPKCS8SignerFromPEM(pemBytes []byte, password []byte) (crypto.Signer, error) {
	if len(password) == 0 {
		return nil, errors.New("password is required for ENCRYPTED PRIVATE KEY")
	}

	for len(pemBytes) > 0 {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != "ENCRYPTED PRIVATE KEY" {
			continue
		}

		keyAny, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, password)
		if err != nil {
			return nil, fmt.Errorf("decrypt PKCS#8 encrypted private key: %w", err)
		}

		switch k := keyAny.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported key type in PKCS#8: %T (expected RSA or ECDSA)", keyAny)
		}
	}

	return nil, errors.New("no ENCRYPTED PRIVATE KEY block found in PEM")
}
