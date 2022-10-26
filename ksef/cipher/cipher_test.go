package cipher

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRsaCipher(t *testing.T) {

	cipher, err := RsaEncrypt([]byte("Ala ma kota"), "../../data/mfkeys/test/publicKey.pem")
	if err != nil {
		t.Errorf("problem with encrypt %v", err)
	}

	fmt.Println(hex.EncodeToString(cipher))
}

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
