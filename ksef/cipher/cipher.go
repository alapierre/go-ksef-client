package cipher

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func AesCipher(plaintext string, key []byte) ([]byte, error) {

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cannot create AES cipher from given key: %v", err)
	}

	encrypted := make([]byte, len(plaintext))
	c.Encrypt(encrypted, []byte(plaintext))

	return encrypted, nil
}

func RsaCipher(message []byte, keyFileName string) ([]byte, error) {

	key, err := os.ReadFile(keyFileName)
	if err != nil {
		return nil, fmt.Errorf("cannot read public key file %s: %v", keyFileName, err)
	}

	block, _ := pem.Decode(key)
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse public key from %s: %v", keyFileName, err)
	}

	var publicKey *rsa.PublicKey
	var ok bool
	if publicKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("cannot parse public key: %v", err)
	}
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt given message with public key: %v", err)
	}

	return encrypted, nil
}
