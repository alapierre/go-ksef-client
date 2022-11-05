package api

import (
	"encoding/base64"
	"fmt"
	"go-ksef/ksef/cipher"
	"go-ksef/ksef/model"
	"testing"
	"time"
)

func TestAuthorisationChallenge(t *testing.T) {

	challenge, err := session.AuthorisationChallenge(identifier, model.ONIP)
	if err != nil {
		t.Errorf("błąd %v", err)
	}

	fmt.Printf("res: %#v\n", challenge)
}

func Test_encodeSessionToken(t *testing.T) {

	challengeTimestamp, err := time.Parse(time.RFC3339, "2022-10-23T17:53:52.560Z")
	if err != nil {
		t.Errorf("can't parse timestamp")
	}

	encrypted, err := encodeAuthToken(
		token,
		challengeTimestamp,
		"../../data/mfkeys/test/publicKey.pem")

	if err != nil {
		t.Errorf("can't encrypt")
	}

	fmt.Println(base64.StdEncoding.EncodeToString(encrypted))
}

func TestSessionLoginByToken(t *testing.T) {
	sessionToken, err := session.LoginByToken(
		identifier,
		model.ONIP,
		token,
		"../../data/mfkeys/test/publicKey.pem")

	if err != nil {
		t.Errorf("can't login %v", err)
	}

	fmt.Printf("%v", sessionToken)
}

func TestSessionLoginByTokenWithEnc(t *testing.T) {
	aes, err := cipher.AesWithRandomKey(32)
	if err != nil {
		t.Errorf("can't prepare AES Encryptor: %v", err)
	}

	sessionEncrypted := NewSessionServiceWithEncryption(apiClient, aes)

	sessionToken, err := sessionEncrypted.LoginByToken(
		identifier,
		model.ONIP,
		token,
		"../../data/mfkeys/test/publicKey.pem")

	if err != nil {
		t.Errorf("can't login %v", err)
	}

	fmt.Printf("%#v", sessionToken)

}
