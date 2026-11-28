package ksef

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
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

func TestEncryptKsefTokenWithKeyIDPreservesCertificateRateLimit(t *testing.T) {
	for _, tc := range []struct{ contentType, body string }{
		{"application/json", `{"status":{"code":429,"description":"Too Many Requests","details":[]}}`},
		{"application/problem+json", `{"title":"Too Many Requests","status":429,"detail":"Limit exceeded","instance":"/request/1","timestamp":"2026-07-01T00:00:00Z","traceId":"trace-1"}`},
	} {
		t.Run(tc.contentType, func(t *testing.T) {
			client := &http.Client{Transport: testRoundTripper(func(*http.Request) (*http.Response, error) {
				resp := testJSONResponse(http.StatusTooManyRequests, tc.contentType, tc.body)
				resp.Header.Set("Retry-After", "17")
				return resp, nil
			})}
			s, err := NewEncryptionService(Test, client)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.EncryptKsefTokenWithKeyID(context.Background(), "token", time.Now())
			var apiErr *ApiError
			if !errors.As(err, &apiErr) || apiErr.Status != http.StatusTooManyRequests || apiErr.RetryAfter.Or(0) != 17 {
				t.Fatalf("expected 429 with Retry-After 17, got %#v (%v)", apiErr, err)
			}
		})
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
