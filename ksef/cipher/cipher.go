package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type AesCipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Key() []byte
	Iv() []byte
}

type aesCipher struct {
	key []byte
	iv  []byte

	c cipher.Block
}

func NewAes(keySize int) (AesCipher, error) {

	c := &aesCipher{
		key: make([]byte, keySize),
		iv:  make([]byte, 16),
		c:   nil,
	}

	if _, err := rand.Read(c.key); err != nil {
		return nil, fmt.Errorf("AES random key creation error, %v", err)
	}
	if _, err := rand.Read(c.iv); err != nil {
		return nil, fmt.Errorf("AES random iv creation error, %v", err)
	}

	var err error
	c.c, err = aes.NewCipher(c.key)
	return c, err
}

func (aes *aesCipher) Encrypt(plaintext []byte) ([]byte, error) {

	plaintext, err := PKCS7Padding(plaintext, aes.c.BlockSize())
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, len(plaintext))

	encryptor := cipher.NewCBCEncrypter(aes.c, aes.iv)
	encryptor.CryptBlocks(encrypted, plaintext)

	return encrypted, nil
}

func (aes *aesCipher) Key() []byte {
	return aes.key
}

func (aes *aesCipher) Iv() []byte {
	return aes.iv
}

func AesDecrypt(encrypted, key, iv []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(encrypted))
	decrypt := cipher.NewCBCDecrypter(block, iv)
	decrypt.CryptBlocks(plaintext, encrypted)

	plaintext = PKCS7UnPadding(plaintext)
	return plaintext, nil
}

func RsaEncrypt(message []byte, keyFileName string) ([]byte, error) {

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

func PKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid blockSize")
	}
	if data == nil || len(data) == 0 {
		return nil, fmt.Errorf("invalid PKCS7 data (empty or not padded)")
	}
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...), nil
}

func PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	unPadding := int(plantText[length-1])
	return plantText[:(length - unPadding)]
}
