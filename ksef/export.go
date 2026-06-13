package ksef

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/alapierre/go-ksef-client/ksef/aes"
	"github.com/alapierre/go-ksef-client/ksef/api"
)

var ErrInvoiceExportExpired = errors.New("ksef invoice export expired")

type InvoiceExport struct {
	ReferenceNumber string
	Key             []byte
	IV              []byte
	Response        *api.ExportInvoicesResponse
}

type InvoiceExportDownloadResult struct {
	Package      api.InvoicePackage
	Parts        []InvoiceExportPartResult
	BytesWritten int64
	InvoiceCount int64
	IsTruncated  bool
}

type InvoiceExportPartResult struct {
	OrdinalNumber     int32
	PartName          string
	PlainSize         int64
	EncryptedSize     int64
	PlainSHA256       []byte
	EncryptedSHA256   []byte
	HTTPStatusCode    int
	EncryptedHashFrom string
}

func (c *Client) StartInvoiceExport(ctx context.Context, filters api.InvoiceQueryFilters, onlyMetadata api.OptBool, key, iv []byte) (*InvoiceExport, error) {
	enc, err := c.encryptor.BuildEncryptionInfo(ctx, key, iv)
	if err != nil {
		return nil, err
	}

	res, err := c.startInvoiceExport(ctx, filters, onlyMetadata, enc, key, iv)
	if !IsPublicKeyRejectedError(err) {
		return res, err
	}

	logger.Info("Public key rejected, refreshing encryption key")

	if refreshErr := c.encryptor.ForceRefresh(ctx); refreshErr != nil {
		return nil, refreshErr
	}
	enc, err = c.encryptor.BuildEncryptionInfo(ctx, key, iv)
	if err != nil {
		return nil, err
	}
	return c.startInvoiceExport(ctx, filters, onlyMetadata, enc, key, iv)
}

func (c *Client) StartInvoiceExportWithGeneratedKey(ctx context.Context, filters api.InvoiceQueryFilters, onlyMetadata api.OptBool) (*InvoiceExport, error) {
	key, err := aes.GenerateRandom256BitsKey()
	if err != nil {
		return nil, err
	}
	iv, err := aes.GenerateRandom16BytesIv()
	if err != nil {
		return nil, err
	}
	return c.StartInvoiceExport(ctx, filters, onlyMetadata, key, iv)
}

func (c *Client) startInvoiceExport(ctx context.Context, filters api.InvoiceQueryFilters, onlyMetadata api.OptBool, enc api.EncryptionInfo, key, iv []byte) (*InvoiceExport, error) {
	req := api.OptInvoiceExportRequest{}
	req.SetTo(api.InvoiceExportRequest{
		Encryption:   enc,
		OnlyMetadata: onlyMetadata,
		Filters:      filters,
	})

	res, err := c.raw.InvoicesExportsPost(ctx, req)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.ExportInvoicesResponse:
		return &InvoiceExport{
			ReferenceNumber: string(v.GetReferenceNumber()),
			Key:             bytes.Clone(key),
			IV:              bytes.Clone(iv),
			Response:        v,
		}, nil
	case *api.UnauthorizedProblemDetails:
		return nil, ErrUnauthorized
	case *api.ForbiddenProblemDetails:
		return nil, ErrForbidden
	case *api.ExceptionResponse:
		return nil, HandleAPIError(v)
	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

func (c *Client) InvoiceExportStatus(ctx context.Context, reference string) (*api.InvoiceExportStatusResponse, error) {
	params := api.InvoicesExportsReferenceNumberGetParams{
		ReferenceNumber: api.ReferenceNumber(reference),
	}

	res, err := c.raw.InvoicesExportsReferenceNumberGet(ctx, params)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.InvoiceExportStatusResponse:
		return v, nil
	case *api.UnauthorizedProblemDetails:
		return nil, ErrUnauthorized
	case *api.ForbiddenProblemDetails:
		return nil, ErrForbidden
	case *api.GoneProblemDetails:
		return nil, ErrInvoiceExportExpired
	case *api.ExceptionResponse:
		return nil, HandleAPIError(v)
	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

func (c *Client) DownloadInvoiceExport(ctx context.Context, status *api.InvoiceExportStatusResponse, key, iv []byte, w io.Writer) (*InvoiceExportDownloadResult, error) {
	if status == nil {
		return nil, fmt.Errorf("invoice export status is nil")
	}
	if w == nil {
		return nil, fmt.Errorf("invoice export writer is nil")
	}
	if code := status.GetStatus().Code; code != 200 {
		return nil, fmt.Errorf("invoice export is not ready, status code %d: %s", code, status.GetStatus().Description)
	}

	pkg, ok := status.GetPackage().Get()
	if !ok {
		return nil, fmt.Errorf("invoice export status does not contain package")
	}

	parts := append([]api.InvoicePackagePart(nil), pkg.GetParts()...)
	sort.Slice(parts, func(i, j int) bool {
		return parts[i].GetOrdinalNumber() < parts[j].GetOrdinalNumber()
	})

	result := &InvoiceExportDownloadResult{
		Package:      pkg,
		InvoiceCount: pkg.GetInvoiceCount(),
		IsTruncated:  pkg.GetIsTruncated(),
	}

	for _, part := range parts {
		partResult, err := c.downloadInvoiceExportPart(ctx, part, key, iv, w)
		if err != nil {
			return result, err
		}
		result.Parts = append(result.Parts, *partResult)
		result.BytesWritten += partResult.PlainSize
	}

	if pkg.GetSize() > 0 && result.BytesWritten != pkg.GetSize() {
		return result, fmt.Errorf("invoice export package size mismatch: got %d, want %d", result.BytesWritten, pkg.GetSize())
	}

	return result, nil
}

func (c *Client) downloadInvoiceExportPart(ctx context.Context, part api.InvoicePackagePart, key, iv []byte, w io.Writer) (*InvoiceExportPartResult, error) {
	method := part.GetMethod()
	if method == "" {
		method = http.MethodGet
	}

	partURL := part.GetURL()
	urlStr := partURL.String()
	req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for export part %d (%s) failed: %w", part.GetOrdinalNumber(), urlStr, err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading export part %d (%s) failed: %w", part.GetOrdinalNumber(), urlStr, err)
	}
	defer resp.Body.Close()

	encrypted, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading export part %d failed: %w", part.GetOrdinalNumber(), err)
	}

	result := &InvoiceExportPartResult{
		OrdinalNumber:  part.GetOrdinalNumber(),
		PartName:       part.GetPartName(),
		EncryptedSize:  int64(len(encrypted)),
		HTTPStatusCode: resp.StatusCode,
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return result, fmt.Errorf("downloading export part %d failed: HTTP %d", part.GetOrdinalNumber(), resp.StatusCode)
	}

	if want := part.GetEncryptedPartSize(); want > 0 && int64(len(encrypted)) != want {
		return result, fmt.Errorf("encrypted export part %d size mismatch: got %d, want %d", part.GetOrdinalNumber(), len(encrypted), want)
	}

	encryptedSum := sha256.Sum256(encrypted)
	result.EncryptedSHA256 = bytes.Clone(encryptedSum[:])
	if want := []byte(part.GetEncryptedPartHash()); len(want) > 0 && !bytes.Equal(encryptedSum[:], want) {
		return result, fmt.Errorf("encrypted export part %d hash mismatch", part.GetOrdinalNumber())
	}

	if headerHash := resp.Header.Get("x-ms-meta-hash"); headerHash != "" {
		result.EncryptedHashFrom = "x-ms-meta-hash"
		decoded, decodeErr := base64.StdEncoding.DecodeString(headerHash)
		if decodeErr != nil {
			return result, fmt.Errorf("decode x-ms-meta-hash for export part %d: %w", part.GetOrdinalNumber(), decodeErr)
		}
		if !bytes.Equal(encryptedSum[:], decoded) {
			return result, fmt.Errorf("encrypted export part %d x-ms-meta-hash mismatch", part.GetOrdinalNumber())
		}
	}

	plain, err := aes.DecryptBytesAESCBCPKCS5(encrypted, key, iv)
	if err != nil {
		return result, fmt.Errorf("decrypt export part %d: %w", part.GetOrdinalNumber(), err)
	}

	result.PlainSize = int64(len(plain))
	if want := part.GetPartSize(); want > 0 && int64(len(plain)) != want {
		return result, fmt.Errorf("export part %d size mismatch after decrypt: got %d, want %d", part.GetOrdinalNumber(), len(plain), want)
	}

	plainSum := sha256.Sum256(plain)
	result.PlainSHA256 = bytes.Clone(plainSum[:])
	if want := []byte(part.GetPartHash()); len(want) > 0 && !bytes.Equal(plainSum[:], want) {
		return result, fmt.Errorf("export part %d hash mismatch after decrypt", part.GetOrdinalNumber())
	}

	if _, err := io.Copy(w, bytes.NewReader(plain)); err != nil {
		return result, fmt.Errorf("write decrypted export part %d: %w", part.GetOrdinalNumber(), err)
	}

	return result, nil
}
