package ksef

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/alapierre/go-ksef-client/ksef/aes"
	"github.com/alapierre/go-ksef-client/ksef/api"
)

func TestDownloadInvoiceExportDecryptsAndJoinsParts(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	iv := bytes.Repeat([]byte{0x22}, 16)
	plainPackage := []byte("PK\x03\x04first zip fragment and second zip fragment")

	plainParts := [][]byte{
		plainPackage[:19],
		plainPackage[19:],
	}

	encryptedParts := make([][]byte, len(plainParts))
	for i, part := range plainParts {
		encrypted, err := aes.EncryptBytesWithAES256CBCPKCS7(part, key, iv)
		if err != nil {
			t.Fatalf("encrypt part %d: %v", i, err)
		}
		encryptedParts[i] = encrypted
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var idx int
		switch r.URL.Path {
		case "/part-0":
			idx = 0
		case "/part-1":
			idx = 1
		default:
			http.NotFound(w, r)
			return
		}

		hash := sha256.Sum256(encryptedParts[idx])
		w.Header().Set("x-ms-meta-hash", base64.StdEncoding.EncodeToString(hash[:]))
		_, _ = w.Write(encryptedParts[idx])
	}))
	defer server.Close()

	part := func(idx int) api.InvoicePackagePart {
		partURL, err := url.Parse(fmt.Sprintf("%s/part-%d", server.URL, idx))
		if err != nil {
			t.Fatalf("parse URL: %v", err)
		}
		plainHash := sha256.Sum256(plainParts[idx])
		encryptedHash := sha256.Sum256(encryptedParts[idx])
		return api.InvoicePackagePart{
			OrdinalNumber:     int32(idx),
			PartName:          fmt.Sprintf("part-%d", idx),
			Method:            http.MethodGet,
			URL:               *partURL,
			PartSize:          int64(len(plainParts[idx])),
			PartHash:          plainHash[:],
			EncryptedPartSize: int64(len(encryptedParts[idx])),
			EncryptedPartHash: encryptedHash[:],
		}
	}

	status := &api.InvoiceExportStatusResponse{
		Status: api.StatusInfo{
			Code:        200,
			Description: "done",
		},
		Package: api.NewOptNilInvoicePackage(api.InvoicePackage{
			InvoiceCount: 1,
			Size:         int64(len(plainPackage)),
			Parts: []api.InvoicePackagePart{
				part(1),
				part(0),
			},
		}),
	}

	client := &Client{httpClient: server.Client()}
	var out bytes.Buffer
	result, err := client.DownloadInvoiceExport(context.Background(), status, key, iv, &out)
	if err != nil {
		t.Fatalf("DownloadInvoiceExport failed: %v", err)
	}

	if !bytes.Equal(out.Bytes(), plainPackage) {
		t.Fatalf("unexpected package content: got %q, want %q", out.Bytes(), plainPackage)
	}
	if result.BytesWritten != int64(len(plainPackage)) {
		t.Fatalf("unexpected bytes written: got %d, want %d", result.BytesWritten, len(plainPackage))
	}
	if len(result.Parts) != 2 {
		t.Fatalf("unexpected parts count: got %d, want 2", len(result.Parts))
	}
}
