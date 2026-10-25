package api

import (
	"bytes"
	"testing"
)

func TestBase64StringLengthValidation(t *testing.T) {
	validators := map[string]func([]byte) error{
		"hash": func(value []byte) error { return Sha256HashBase64(value).Validate() },
		"online": func(value []byte) error {
			return (&SessionsOnlinePostReqEncryption{PublicKeyId: NewOptNilByte(value)}).Validate()
		},
		"batch": func(value []byte) error {
			return (&SessionsBatchPostReqEncryption{PublicKeyId: NewOptNilByte(value)}).Validate()
		},
		"export": func(value []byte) error {
			return (&InvoicesExportsPostReqEncryption{PublicKeyId: NewOptNilByte(value)}).Validate()
		},
		"token": func(value []byte) error {
			return (&AuthKsefTokenPostReq{Challenge: "20250514-CR-226FB7B000-3ACF9BE4C0-10", ContextIdentifier: AuthKsefTokenPostReqContextIdentifier{Type: AuthenticationContextIdentifierTypeNip, Value: "1111111111"}, PublicKeyId: NewOptNilByte(value)}).Validate()
		},
		"certificate": func(value []byte) error {
			return (&PublicKeyCertificate{PublicKeyId: value, Usage: []PublicKeyCertificateUsage{PublicKeyCertificateUsageKsefTokenEncryption}}).Validate()
		},
	}
	for name, validate := range validators {
		t.Run(name, func(t *testing.T) {
			// 32 binary bytes encode to 44 characters; checking the raw bytes is wrong.
			if err := validate(bytes.Repeat([]byte{0xff}, 32)); err != nil {
				t.Fatalf("valid Base64 field rejected: %v", err)
			}
			for _, size := range []int{1, 44} {
				if err := validate(bytes.Repeat([]byte{'a'}, size)); err == nil {
					t.Errorf("accepted %d raw bytes with invalid encoded length", size)
				}
			}
		})
	}
}
