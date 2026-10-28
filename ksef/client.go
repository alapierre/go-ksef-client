package ksef

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/alapierre/go-ksef-client/ksef/aes"
	"github.com/alapierre/go-ksef-client/ksef/api"
)

type Client struct {
	raw        *api.Client
	env        Environment
	httpClient *http.Client
	encryptor  *EncryptionService
}

type ClientOption func(*Client)

func WithEncryptionService(encryptor *EncryptionService) ClientOption {
	return func(c *Client) {
		c.encryptor = encryptor
	}
}

func NewClient(env Environment, httpClient *http.Client, sec api.SecuritySource, opts ...ClientOption) (*Client, error) {
	cli, err := api.NewClient(
		env.BaseURL(),
		sec,
		api.WithClient(httpClient),
	)
	if err != nil {
		return nil, err
	}

	c := &Client{raw: cli, env: env, httpClient: httpClient}
	for _, opt := range opts {
		opt(c)
	}
	if c.encryptor == nil {
		c.encryptor, err = NewEncryptionService(env, httpClient)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (c *Client) OpenInteractiveSession(ctx context.Context, form api.FormCode, symmetricKey, iv []byte) (*api.OpenOnlineSessionResponse, error) {
	result, _, err := c.OpenInteractiveSessionWithMetadata(ctx, form, symmetricKey, iv)
	return result, err
}

// OpenInteractiveSessionWithMetadata is OpenInteractiveSession with successful response headers.
func (c *Client) OpenInteractiveSessionWithMetadata(ctx context.Context, form api.FormCode, symmetricKey, iv []byte) (*api.OpenOnlineSessionResponse, ResponseMetadata, error) {
	enc, err := c.encryptor.BuildEncryptionInfo(ctx, symmetricKey, iv)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}

	res, metadata, err := c.openInteractiveSessionWithMetadata(ctx, form, enc)
	if !IsPublicKeyRejectedError(err) {
		return res, metadata, err
	}

	logger.Info("Public key rejected, refreshing encryption key")

	if refreshErr := c.encryptor.ForceRefresh(ctx); refreshErr != nil {
		return nil, ResponseMetadata{}, refreshErr
	}
	enc, err = c.encryptor.BuildEncryptionInfo(ctx, symmetricKey, iv)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}
	return c.openInteractiveSessionWithMetadata(ctx, form, enc)
}

func (c *Client) openInteractiveSession(ctx context.Context, form api.FormCode, enc api.EncryptionInfo) (*api.OpenOnlineSessionResponse, error) {
	result, _, err := c.openInteractiveSessionWithMetadata(ctx, form, enc)
	return result, err
}

// openInteractiveSessionWithMetadata is openInteractiveSession with successful response headers.
func (c *Client) openInteractiveSessionWithMetadata(ctx context.Context, form api.FormCode, enc api.EncryptionInfo) (*api.OpenOnlineSessionResponse, ResponseMetadata, error) {
	req := api.OptOpenOnlineSessionRequest{}
	req.SetTo(api.OpenOnlineSessionRequest{
		FormCode:   form,
		Encryption: enc,
	})

	res, err := c.raw.SessionsOnlinePost(ctx, req)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}

	switch v := res.(type) {
	case *api.OpenOnlineSessionResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

func (c *Client) SendInvoice(ctx context.Context, reference string, offline api.OptBool, invoice, key, iv []byte) (string, error) {
	result, _, err := c.SendInvoiceWithMetadata(ctx, reference, offline, invoice, key, iv)
	return result, err
}

// SendInvoiceWithMetadata is SendInvoice with successful response headers.
func (c *Client) SendInvoiceWithMetadata(ctx context.Context, reference string, offline api.OptBool, invoice, key, iv []byte) (string, ResponseMetadata, error) {

	encrypted, err := aes.EncryptBytesWithAES256CBCPKCS7(invoice, key, iv)
	if err != nil {
		return "", ResponseMetadata{}, err
	}

	im := aes.GetMetadata(invoice)
	em := aes.GetMetadata(encrypted)

	req := api.OptSendInvoiceRequest{}
	req.SetTo(api.SendInvoiceRequest{
		InvoiceHash:             im.HashSHA,
		InvoiceSize:             im.Size,
		EncryptedInvoiceHash:    em.HashSHA,
		EncryptedInvoiceSize:    em.Size,
		EncryptedInvoiceContent: encrypted,
		OfflineMode:             offline,
	})

	params := api.SessionsOnlineReferenceNumberInvoicesPostParams{
		ReferenceNumber: api.ReferenceNumber(reference),
	}

	res, err := c.raw.SessionsOnlineReferenceNumberInvoicesPost(ctx, req, params)
	if err != nil {
		return "", ResponseMetadata{}, err
	}

	switch v := res.(type) {
	case *api.SendInvoiceResponseHeaders:
		return string(v.Response.GetReferenceNumber()), responseMetadata(v), nil
	default:
		return "", ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

func (c *Client) CloseInteractiveSession(ctx context.Context, reference string) (string, error) {
	result, _, err := c.CloseInteractiveSessionWithMetadata(ctx, reference)
	return result, err
}

// CloseInteractiveSessionWithMetadata is CloseInteractiveSession with successful response headers.
func (c *Client) CloseInteractiveSessionWithMetadata(ctx context.Context, reference string) (string, ResponseMetadata, error) {
	params := api.SessionsOnlineReferenceNumberClosePostParams{
		ReferenceNumber: api.ReferenceNumber(reference),
	}

	res, err := c.raw.SessionsOnlineReferenceNumberClosePost(ctx, params)
	if err != nil {
		return "", ResponseMetadata{}, err
	}

	switch v := res.(type) {
	case *api.SessionsOnlineReferenceNumberClosePostNoContent:
		return reference, responseMetadata(v), nil
	default:
		return "", ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

func (c *Client) SessionInvoices(ctx context.Context, reference string, continuationToken api.OptString, pageSize api.OptInt32) (*api.SessionInvoicesResponse, error) {
	result, _, err := c.SessionInvoicesWithMetadata(ctx, reference, continuationToken, pageSize)
	return result, err
}

// SessionInvoicesWithMetadata is SessionInvoices with successful response headers.
func (c *Client) SessionInvoicesWithMetadata(ctx context.Context, reference string, continuationToken api.OptString, pageSize api.OptInt32) (*api.SessionInvoicesResponse, ResponseMetadata, error) {
	params := api.SessionsReferenceNumberInvoicesGetParams{
		XContinuationToken: continuationToken,
		ReferenceNumber:    api.ReferenceNumber(reference),
		PageSize:           pageSize,
	}

	res, err := c.raw.SessionsReferenceNumberInvoicesGet(ctx, params)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}

	switch v := res.(type) {
	case *api.SessionInvoicesResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

func (c *Client) QueryInvoicesMetadata(ctx context.Context, filters api.InvoiceQueryFilters, params api.InvoicesQueryMetadataPostParams) (*api.QueryInvoicesMetadataResponse, error) {
	result, _, err := c.QueryInvoicesMetadataWithMetadata(ctx, filters, params)
	return result, err
}

// QueryInvoicesMetadataWithMetadata is QueryInvoicesMetadata with successful response headers.
func (c *Client) QueryInvoicesMetadataWithMetadata(ctx context.Context, filters api.InvoiceQueryFilters, params api.InvoicesQueryMetadataPostParams) (*api.QueryInvoicesMetadataResponse, ResponseMetadata, error) {
	req := api.OptInvoiceQueryFilters{}
	req.SetTo(filters)

	res, err := c.raw.InvoicesQueryMetadataPost(ctx, req, params)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}

	switch v := res.(type) {
	case *api.QueryInvoicesMetadataResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

func (c *Client) GetInvoiceByKsefNumber(ctx context.Context, ksefNumber string) (*api.InvoicesKsefKsefNumberGetOKHeaders, error) {
	result, _, err := c.GetInvoiceByKsefNumberWithMetadata(ctx, ksefNumber)
	return result, err
}

// GetInvoiceByKsefNumberWithMetadata is GetInvoiceByKsefNumber with successful response headers.
func (c *Client) GetInvoiceByKsefNumberWithMetadata(ctx context.Context, ksefNumber string) (*api.InvoicesKsefKsefNumberGetOKHeaders, ResponseMetadata, error) {
	params := api.InvoicesKsefKsefNumberGetParams{
		KsefNumber: api.KsefNumber(ksefNumber),
	}

	res, err := c.raw.InvoicesKsefKsefNumberGet(ctx, params)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}

	switch v := res.(type) {
	case *api.InvoicesKsefKsefNumberGetOKHeaders:
		return v, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

func (c *Client) GetUPO(ctx context.Context, reference, upoReference string) (*api.SessionsReferenceNumberUpoUpoReferenceNumberGetOKHeaders, error) {
	result, _, err := c.GetUPOWithMetadata(ctx, reference, upoReference)
	return result, err
}

// GetUPOWithMetadata is GetUPO with successful response headers.
func (c *Client) GetUPOWithMetadata(ctx context.Context, reference, upoReference string) (*api.SessionsReferenceNumberUpoUpoReferenceNumberGetOKHeaders, ResponseMetadata, error) {
	params := api.SessionsReferenceNumberUpoUpoReferenceNumberGetParams{
		ReferenceNumber:    api.ReferenceNumber(reference),
		UpoReferenceNumber: api.ReferenceNumber(upoReference),
	}

	res, err := c.raw.SessionsReferenceNumberUpoUpoReferenceNumberGet(ctx, params)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}

	switch v := res.(type) {
	case *api.SessionsReferenceNumberUpoUpoReferenceNumberGetOKHeaders:
		return v, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

func (c *Client) OpenBatchSession(ctx context.Context, form api.FormCode, symmetricKey, iv []byte, offline api.OptBool, info api.BatchFileInfo) (*api.OpenBatchSessionResponse, error) {
	result, _, err := c.OpenBatchSessionWithMetadata(ctx, form, symmetricKey, iv, offline, info)
	return result, err
}

// OpenBatchSessionWithMetadata is OpenBatchSession with successful response headers.
func (c *Client) OpenBatchSessionWithMetadata(ctx context.Context, form api.FormCode, symmetricKey, iv []byte, offline api.OptBool, info api.BatchFileInfo) (*api.OpenBatchSessionResponse, ResponseMetadata, error) {
	enc, err := c.encryptor.BuildEncryptionInfo(ctx, symmetricKey, iv)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}

	res, metadata, err := c.openBatchSessionWithMetadata(ctx, form, enc, offline, info)
	if !IsPublicKeyRejectedError(err) {
		return res, metadata, err
	}

	logger.Info("Public key rejected, refreshing encryption key")

	if refreshErr := c.encryptor.ForceRefresh(ctx); refreshErr != nil {
		return nil, ResponseMetadata{}, refreshErr
	}
	enc, err = c.encryptor.BuildEncryptionInfo(ctx, symmetricKey, iv)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}
	return c.openBatchSessionWithMetadata(ctx, form, enc, offline, info)
}

func (c *Client) openBatchSession(ctx context.Context, form api.FormCode, enc api.EncryptionInfo, offline api.OptBool, info api.BatchFileInfo) (*api.OpenBatchSessionResponse, error) {
	result, _, err := c.openBatchSessionWithMetadata(ctx, form, enc, offline, info)
	return result, err
}

// openBatchSessionWithMetadata is openBatchSession with successful response headers.
func (c *Client) openBatchSessionWithMetadata(ctx context.Context, form api.FormCode, enc api.EncryptionInfo, offline api.OptBool, info api.BatchFileInfo) (*api.OpenBatchSessionResponse, ResponseMetadata, error) {

	req := api.OptOpenBatchSessionRequest{}

	req.SetTo(api.OpenBatchSessionRequest{
		FormCode:    api.SessionsBatchPostReqFormCode(form),
		BatchFile:   info,
		Encryption:  api.SessionsBatchPostReqEncryption(enc),
		OfflineMode: offline,
	})

	res, err := c.raw.SessionsBatchPost(ctx, req)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}

	switch v := res.(type) {
	case *api.OpenBatchSessionResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

func (c *Client) SendBatchPart(ctx context.Context, data []byte, info api.PartUploadRequest) (*BatchPartResult, error) {

	urlStr := info.URL.String()

	req, err := http.NewRequestWithContext(ctx, info.Method, urlStr, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request for part %d (%s) failed: %w",
			info.OrdinalNumber, urlStr, err)
	}

	for k, v := range info.Headers {
		req.Header.Set(k, v.Value)
	}

	// Set Content-Type: application/octet-stream, if not set already
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request for part %d (%s) failed: %w",
			info.OrdinalNumber, urlStr, err)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		logger.Warningf("reading response for part %d (%s) failed: %v", info.OrdinalNumber, urlStr, readErr)
	}

	result := &BatchPartResult{
		OrdinalNumber: info.OrdinalNumber,
		URL:           urlStr,
		StatusCode:    resp.StatusCode,
		Body:          body,
		Message:       string(body),
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return result, fmt.Errorf("error sending part %d: HTTP %d", info.OrdinalNumber, resp.StatusCode)
	}

	return result, nil
}

func (c *Client) CloseBatchSession(ctx context.Context, reference string) (string, error) {
	result, _, err := c.CloseBatchSessionWithMetadata(ctx, reference)
	return result, err
}

// CloseBatchSessionWithMetadata is CloseBatchSession with successful response headers.
func (c *Client) CloseBatchSessionWithMetadata(ctx context.Context, reference string) (string, ResponseMetadata, error) {

	req := api.SessionsBatchReferenceNumberClosePostParams{
		ReferenceNumber: api.ReferenceNumber(reference),
	}

	res, err := c.raw.SessionsBatchReferenceNumberClosePost(ctx, req)
	if err != nil {
		return "", ResponseMetadata{}, err
	}

	switch v := res.(type) {
	case *api.SessionsBatchReferenceNumberClosePostNoContent:
		// sukces – API zwraca 204 bez treści
		return reference, responseMetadata(v), nil
	default:
		return "", ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

type BatchPartResult struct {
	OrdinalNumber int32
	URL           string
	StatusCode    int
	Message       string
	Body          []byte
}
