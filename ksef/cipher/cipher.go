package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	log "github.com/sirupsen/logrus"
)

type AesCipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(encrypted []byte) ([]byte, error)
	Key() []byte
	Iv() []byte
}

type aesCipher struct {
	key []byte
	iv  []byte

	block cipher.Block
}

// AesWithRandomKey creates and initialize AES cipher with random key and iv.
// The keySize argument should be either 16, 24, or 32 bytes
// to select AES-128, AES-192, or AES-256
func AesWithRandomKey(keySize int) (AesCipher, error) {

	log.Debug("Creating AES Cipher with random key and iv")

	c := &aesCipher{
		key:   make([]byte, keySize),
		iv:    make([]byte, aes.BlockSize),
		block: nil,
	}

	if _, err := rand.Read(c.key); err != nil {
		return nil, fmt.Errorf("AES random key creation error, %v", err)
	}
	if _, err := rand.Read(c.iv); err != nil {
		return nil, fmt.Errorf("AES random iv creation error, %v", err)
	}

	var err error
	c.block, err = aes.NewCipher(c.key)
	return c, err
}

// NewAes creates and initialize AES cipher.
// The key argument should be the AES key, either 16, 24, or 32 bytes
// to select AES-128, AES-192, or AES-256.
// The length of iv must be the same as the Block's block size (16 bytes).
func NewAes(key, iv []byte) (AesCipher, error) {

	log.Debug("Creating AES Cipher with given key and iv")

	c := &aesCipher{
		key:   key,
		iv:    iv,
		block: nil,
	}

	var err error
	c.block, err = aes.NewCipher(c.key)
	return c, err
}

// Encrypt given message using AES/CBC/PKCS7 encryption
func (c *aesCipher) Encrypt(message []byte) ([]byte, error) {

	message, err := PKCS7Padding(message, c.block.BlockSize())
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, len(message))

	encryptor := cipher.NewCBCEncrypter(c.block, c.iv)
	encryptor.CryptBlocks(encrypted, message)

	return encrypted, nil
}

// Key gets AES key
func (c *aesCipher) Key() []byte {
	return c.key
}

// Iv gets AES iv
func (c *aesCipher) Iv() []byte {
	return c.iv
}

// Decrypt decrypt given AES/CBC/PKCS7 encrypted message
func (c *aesCipher) Decrypt(encrypted []byte) ([]byte, error) {

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(encrypted))
	decrypt := cipher.NewCBCDecrypter(block, c.iv)
	decrypt.CryptBlocks(plaintext, encrypted)

	plaintext = PKCS7UnPadding(plaintext)
	return plaintext, nil
}

// PKCS7Padding add the padding to the data before encrypting, to make the input a multiple of the AES block size.
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

// PKCS7UnPadding remove padding before decrypting
func PKCS7UnPadding(plantText []byte) []byte {
	length := len(plantText)
	unPadding := int(plantText[length-1])
	return plantText[:(length - unPadding)]
}
