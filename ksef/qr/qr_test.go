package qr

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/alapierre/go-ksef-client/ksef"
	"github.com/alapierre/go-ksef-client/ksef/rsa"
	"github.com/alapierre/go-ksef-client/ksef/util"
)

func TestSerialFromCert(t *testing.T) {

	cert, err := LoadCertificateFromFile("../../test/test-sign.crt")
	if err != nil {
		t.Fatalf("LoadCertificateFromFile failed: %v", err)
	}

	serial, err := ExtractCertSerial(cert)
	if err != nil {
		t.Fatalf("ExtractCertSerial failed: %v", err)
	}

	fmt.Println(serial)

}

func TestQr2(t *testing.T) {

	pass := util.GetEnvOrFailed("KSEF_CERT_PASS")
	nip := util.GetEnvOrFailed("KSEF_CERT_NIP")
	serial := util.GetEnvOrFailed("KSEF_CERT_SERIAL")

	key, err := rsa.LoadEncryptedPKCS8PrivateKeyFromFile("../../test/test-sign.key", []byte(pass))
	if err != nil {
		t.Fatalf("LoadEncryptedPKCS8PrivateKeyFromFile failed: %v", err)
	}

	sum := sha256.Sum256([]byte("abc"))
	url2, err := GenerateCertificateVerificationLink(
		ksef.Test,
		CtxNip,
		nip,
		nip,
		serial,
		key,
		sum[:],
	)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(url2)

}
