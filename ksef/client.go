package ksef

import (
	"context"
	"fmt"
	"net/http"

	"github.com/alapierre/go-ksef-client/ksef/aes"
	"github.com/alapierre/go-ksef-client/ksef/api"
)

type Client struct {
	raw        *api.Client
	env        Environment
	httpClient *http.Client
}

func NewClient(env Environment, httpClient *http.Client, sec api.SecuritySource) (*Client, error) {
	cli, err := api.NewClient(
		env.BaseURL(),
		sec,
		api.WithClient(httpClient),
	)
	if err != nil {
		return nil, err
	}
	return &Client{raw: cli, env: env, httpClient: httpClient}, nil
}

func (c *Client) OpenInteractiveSession(ctx context.Context, form api.FormCode, enc api.EncryptionInfo) (*api.OpenOnlineSessionResponse, error) {

	req := api.OptOpenOnlineSessionRequest{}
	req.SetTo(api.OpenOnlineSessionRequest{
		FormCode:   form,
		Encryption: enc,
	})

	res, err := c.raw.APIV2SessionsOnlinePost(ctx, req)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.OpenOnlineSessionResponse:
		return v, nil
	case *api.APIV2SessionsOnlinePostUnauthorized:
		return nil, ErrUnauthorized
	case *api.APIV2SessionsOnlinePostForbidden:
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

	params := api.APIV2SessionsOnlineReferenceNumberInvoicesPostParams{
		ReferenceNumber: api.ReferenceNumber(reference),
	}

	res, err := c.raw.APIV2SessionsOnlineReferenceNumberInvoicesPost(ctx, req, params)
	if err != nil {
		return "", err
	}

	switch v := res.(type) {
	case *api.SendInvoiceResponse:
		return string(v.GetReferenceNumber()), nil
	case *api.APIV2SessionsOnlineReferenceNumberInvoicesPostUnauthorized:
		return "", ErrUnauthorized
	case *api.APIV2SessionsOnlineReferenceNumberInvoicesPostForbidden:
		return "", ErrForbidden
	case *api.ExceptionResponse:
		return "", HandleAPIError(v)
	default:
		return "", fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}
