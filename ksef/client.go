package ksef

import (
	"context"
	"fmt"
	"net/http"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

type Client struct {
	raw        *api.Client
	env        Environment
	httpClient *http.Client
}

func New(env Environment, httpClient *http.Client, sec api.SecuritySource) (*Client, error) {
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
