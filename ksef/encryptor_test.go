package ksef

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

func TestBuildEncryptionInfoIncludesPublicKeyID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	publicKeyID := []byte("sym-key-id")
	s := &EncryptionService{refreshSkew: time.Minute}
	WithPreloadedKeys(PreloadedKeys{
		SymmetricRSAPub:      &privateKey.PublicKey,
		SymmetricPublicKeyID: publicKeyID,
		SymmetricValidTo:     time.Now().Add(time.Hour),
	})(s)

	enc, err := s.BuildEncryptionInfo(context.Background(), bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 16))
	if err != nil {
		t.Fatal(err)
	}

	got, ok := enc.PublicKeyId.Get()
	if !ok {
		t.Fatal("publicKeyId is not set")
	}
	if !bytes.Equal(got, publicKeyID) {
		t.Fatalf("publicKeyId = %q, want %q", got, publicKeyID)
	}
	if len(enc.EncryptedSymmetricKey) == 0 {
		t.Fatal("encrypted symmetric key is empty")
	}
}

func TestIsPublicKeyRejectedError(t *testing.T) {
	err := &ApiError{
		Details: []ErrorDetail{
			{Code: PublicKeyRejectedErrorCode, Message: "key rejected"},
		},
	}

	if !IsPublicKeyRejectedError(err) {
		t.Fatal("expected public key rejected error")
	}
}

func TestEncryptionInfoMarshalAcceptsDecodedPublicKeyID(t *testing.T) {
	publicKeyID := bytes.Repeat([]byte{2}, 29)
	enc := api.EncryptionInfo{
		EncryptedSymmetricKey: []byte("encrypted"),
		InitializationVector:  bytes.Repeat([]byte{1}, 16),
		PublicKeyId:           api.NewOptNilByte(publicKeyID),
	}

	data, err := json.Marshal(&enc)
	if err != nil {
		t.Fatalf("EncryptionInfo MarshalJSON failed: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode marshaled EncryptionInfo: %v", err)
	}

	wantPublicKeyID := base64.StdEncoding.EncodeToString(publicKeyID)
	if got["publicKeyId"] != wantPublicKeyID {
		t.Fatalf("publicKeyId = %q, want %q", got["publicKeyId"], wantPublicKeyID)
	}
}
