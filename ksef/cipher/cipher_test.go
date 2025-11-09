package cipher

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAesCipher_Encrypt(t *testing.T) {

	encryptor, err := AesWithRandomKey(32) // 256bits
	if err != nil {
		t.Errorf("can't initialize AES Cipher %v", err)
	}

	encrypted, err := encryptor.Encrypt([]byte("Ala ma kota"))
	if err != nil {
		return
	}

	fmt.Println("encrypted: ", base64.StdEncoding.EncodeToString(encrypted))

	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		return
	}

	fmt.Println("plaintext: ", string(decrypted))
	assert.Equal(t, "Ala ma kota", string(decrypted), "invalid decrypted text")
}
