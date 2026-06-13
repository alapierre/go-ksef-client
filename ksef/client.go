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
	enc, err := c.encryptor.BuildEncryptionInfo(ctx, symmetricKey, iv)
	if err != nil {
		return nil, err
	}

	res, err := c.openInteractiveSession(ctx, form, enc)
	if !IsPublicKeyRejectedError(err) {
		return res, err
	}

	logger.Info("Public key rejected, refreshing encryption key")

	if refreshErr := c.encryptor.ForceRefresh(ctx); refreshErr != nil {
		return nil, refreshErr
	}
	enc, err = c.encryptor.BuildEncryptionInfo(ctx, symmetricKey, iv)
	if err != nil {
		return nil, err
	}
	return c.openInteractiveSession(ctx, form, enc)
}

func (c *Client) openInteractiveSession(ctx context.Context, form api.FormCode, enc api.EncryptionInfo) (*api.OpenOnlineSessionResponse, error) {
	req := api.OptOpenOnlineSessionRequest{}
	req.SetTo(api.OpenOnlineSessionRequest{
		FormCode:   form,
		Encryption: enc,
	})

	res, err := c.raw.SessionsOnlinePost(ctx, req)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.OpenOnlineSessionResponse:
		return v, nil
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

func (c *Client) SendInvoice(ctx context.Context, reference string, offline api.OptBool, invoice, key, iv []byte) (string, error) {

	encrypted, err := aes.EncryptBytesWithAES256CBCPKCS7(invoice, key, iv)
	if err != nil {
		return "", err
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
		return "", err
	}

	switch v := res.(type) {
	case *api.SendInvoiceResponse:
		return string(v.GetReferenceNumber()), nil
	case *api.UnauthorizedProblemDetails:
		return "", ErrUnauthorized
	case *api.ForbiddenProblemDetails:
		return "", ErrForbidden
	case *api.ExceptionResponse:
		return "", HandleAPIError(v)
	default:
		return "", fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

func (c *Client) CloseInteractiveSession(ctx context.Context, reference string) (string, error) {
	params := api.SessionsOnlineReferenceNumberClosePostParams{
		ReferenceNumber: api.ReferenceNumber(reference),
	}

	res, err := c.raw.SessionsOnlineReferenceNumberClosePost(ctx, params)
	if err != nil {
		return "", err
	}

	switch v := res.(type) {
	case *api.SessionsOnlineReferenceNumberClosePostNoContent:
		return reference, nil
	case *api.UnauthorizedProblemDetails:
		return "", ErrUnauthorized
	case *api.ForbiddenProblemDetails:
		return "", ErrForbidden
	case *api.ExceptionResponse:
		return "", HandleAPIError(v)
	default:
		return "", fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

func (c *Client) SessionInvoices(ctx context.Context, reference string, continuationToken api.OptString, pageSize api.OptInt32) (*api.SessionInvoicesResponse, error) {
	params := api.SessionsReferenceNumberInvoicesGetParams{
		XContinuationToken: continuationToken,
		ReferenceNumber:    api.ReferenceNumber(reference),
		PageSize:           pageSize,
	}

	res, err := c.raw.SessionsReferenceNumberInvoicesGet(ctx, params)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.SessionInvoicesResponse:
		return v, nil
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

func (c *Client) QueryInvoicesMetadata(ctx context.Context, filters api.InvoiceQueryFilters, params api.InvoicesQueryMetadataPostParams) (*api.QueryInvoicesMetadataResponse, error) {
	req := api.OptInvoiceQueryFilters{}
	req.SetTo(filters)

	res, err := c.raw.InvoicesQueryMetadataPost(ctx, req, params)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.QueryInvoicesMetadataResponse:
		return v, nil
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

func (c *Client) GetInvoiceByKsefNumber(ctx context.Context, ksefNumber string) (*api.InvoicesKsefKsefNumberGetOKHeaders, error) {
	params := api.InvoicesKsefKsefNumberGetParams{
		KsefNumber: api.KsefNumber(ksefNumber),
	}

	res, err := c.raw.InvoicesKsefKsefNumberGet(ctx, params)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.InvoicesKsefKsefNumberGetOKHeaders:
		return v, nil
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

func (c *Client) GetUPO(ctx context.Context, reference, upoReference string) (*api.SessionsReferenceNumberUpoUpoReferenceNumberGetOKHeaders, error) {
	params := api.SessionsReferenceNumberUpoUpoReferenceNumberGetParams{
		ReferenceNumber:    api.ReferenceNumber(reference),
		UpoReferenceNumber: api.ReferenceNumber(upoReference),
	}

	res, err := c.raw.SessionsReferenceNumberUpoUpoReferenceNumberGet(ctx, params)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.SessionsReferenceNumberUpoUpoReferenceNumberGetOKHeaders:
		return v, nil
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

func (c *Client) OpenBatchSession(ctx context.Context, form api.FormCode, symmetricKey, iv []byte, offline api.OptBool, info api.BatchFileInfo) (*api.OpenBatchSessionResponse, error) {
	enc, err := c.encryptor.BuildEncryptionInfo(ctx, symmetricKey, iv)
	if err != nil {
		return nil, err
	}

	res, err := c.openBatchSession(ctx, form, enc, offline, info)
	if !IsPublicKeyRejectedError(err) {
		return res, err
	}

	logger.Info("Public key rejected, refreshing encryption key")

	if refreshErr := c.encryptor.ForceRefresh(ctx); refreshErr != nil {
		return nil, refreshErr
	}
	enc, err = c.encryptor.BuildEncryptionInfo(ctx, symmetricKey, iv)
	if err != nil {
		return nil, err
	}
	return c.openBatchSession(ctx, form, enc, offline, info)
}

func (c *Client) openBatchSession(ctx context.Context, form api.FormCode, enc api.EncryptionInfo, offline api.OptBool, info api.BatchFileInfo) (*api.OpenBatchSessionResponse, error) {

	req := api.OptOpenBatchSessionRequest{}

	req.SetTo(api.OpenBatchSessionRequest{
		FormCode:    form,
		BatchFile:   info,
		Encryption:  enc,
		OfflineMode: offline,
	})

	res, err := c.raw.SessionsBatchPost(ctx, req)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.OpenBatchSessionResponse:
		return v, nil
	case *api.ExceptionResponse:
		return nil, HandleAPIError(v)
	case *api.UnauthorizedProblemDetails:
		return nil, ErrUnauthorized
	case *api.ForbiddenProblemDetails:
		return nil, ErrForbidden
	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
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

	req := api.SessionsBatchReferenceNumberClosePostParams{
		ReferenceNumber: api.ReferenceNumber(reference),
	}

	res, err := c.raw.SessionsBatchReferenceNumberClosePost(ctx, req)
	if err != nil {
		return "", err
	}

	switch v := res.(type) {
	case *api.SessionsBatchReferenceNumberClosePostNoContent:
		// sukces – API zwraca 204 bez treści
		return reference, nil
	case *api.UnauthorizedProblemDetails:
		return "", ErrUnauthorized
	case *api.ForbiddenProblemDetails:
		return "", ErrForbidden
	case *api.ExceptionResponse:
		return "", HandleAPIError(v)
	default:
		return "", fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

type BatchPartResult struct {
	OrdinalNumber int32
	URL           string
	StatusCode    int
	Message       string
	Body          []byte
}
