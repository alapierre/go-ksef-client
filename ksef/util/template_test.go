package util

import (
	"fmt"
	"go-ksef/ksef/cipher"
	"go-ksef/ksef/model"
	"go-ksef/ksef/tpl"
	"testing"
)

var identifier = GetEnvOrFailed("KSEF_NIP")
var token = GetEnvOrFailed("KSEF_TOKEN")

func TestMergeTemplate(t *testing.T) {

	aes, err := cipher.NewAes(32)
	if err != nil {
		t.Errorf("Can't init AES cipher")
	}

	var dto = model.TokenRequestDTO{
		Identifier: identifier,
		Token:      []byte("encrypted"),
		Challenge:  "20221026-CR-C3CADF764E-CD1519BDA4-01",
		Encryption: model.EncryptionDTO{
			Enabled: false,
			Key:     aes.Key(),
			IV:      aes.Iv(),
		},
	}

	request, err := MergeTemplate(&tpl.InitSessionTokenRequest, dto)
	if err != nil {
		t.Errorf("can't merge template %v", err)
	}

	fmt.Println("merged: ", string(request))
}
