package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/alapierre/go-ksef-client/ksef"
	"github.com/alapierre/go-ksef-client/ksef/api"
	log "github.com/sirupsen/logrus"
)

type Facade struct {
	raw        *api.Client
	env        ksef.Environment
	httpClient *http.Client
}

// Prosty bearer do obsługi pośredniej autoryzacji
type localStaticBearer struct{ Token string }

func (b localStaticBearer) Bearer(ctx context.Context, _ api.OperationName) (api.Bearer, error) {
	return api.Bearer{Token: b.Token}, nil
}

// NewFacade Konstruktor fasady autoryzacyjnej.
func NewFacade(env ksef.Environment, httpClient *http.Client) (*Facade, error) {
	cli, err := api.NewClient(
		env.BaseURL(),
		nil,
		api.WithClient(httpClient),
	)
	if err != nil {
		return nil, err
	}
	return &Facade{raw: cli, env: env, httpClient: httpClient}, nil
}

func (c *Facade) GetChallenge(ctx context.Context) (*api.AuthenticationChallengeResponse, error) {
	res, err := c.raw.APIV2AuthChallengePost(ctx)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.AuthenticationChallengeResponse:
		return v, nil

		// generyczna obsługa błędów (4xx/5xx):
	case *api.ExceptionResponse:
		return nil, ksef.HandleAPIError(v)

	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

func (c *Facade) AuthWithToken(ctx context.Context, challenge api.Challenge, nip ksef.Nip, encryptedTokenBytes []byte) (*api.AuthenticationInitResponse, error) {

	req := api.InitTokenAuthenticationRequest{
		Challenge: challenge,
		ContextIdentifier: api.AuthenticationContextIdentifier{
			Type:  api.AuthenticationContextIdentifierTypeNip,
			Value: string(nip),
		},
		EncryptedToken:      encryptedTokenBytes,
		AuthorizationPolicy: api.OptNilAuthorizationPolicy{},
	}

	optReq := api.NewOptInitTokenAuthenticationRequest(req)

	res, err := c.raw.APIV2AuthKsefTokenPost(ctx, optReq)
	if err != nil {
		return nil, fmt.Errorf("APIV2AuthKsefTokenPost: %w", err)
	}

	switch v := res.(type) {
	case *api.AuthenticationInitResponse:
		return v, nil
	case *api.ExceptionResponse:
		return nil, ksef.HandleAPIError(v)
	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

// AuthWaitAndRedeem Polluje status aż do 200 lub do ctx.Done(). Interwał czekania kontrolowany parametrem pollEvery.
func (c *Facade) AuthWaitAndRedeem(ctx context.Context, authResp *api.AuthenticationInitResponse, pollEvery time.Duration) (*api.AuthenticationTokensResponse, error) {
	if authResp == nil {
		return nil, fmt.Errorf("authResponse is nil")
	}

	cli, err := api.NewClient(
		c.env.BaseURL(),
		localStaticBearer{Token: authResp.GetAuthenticationToken().Token},
		api.WithClient(c.httpClient),
	)
	if err != nil {
		return nil, err
	}

	params := api.APIV2AuthReferenceNumberGetParams{
		ReferenceNumber: authResp.GetReferenceNumber(),
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		case <-time.After(pollEvery):
			res, err := cli.APIV2AuthReferenceNumberGet(ctx, params)
			if err != nil {
				return nil, fmt.Errorf("APIV2AuthReferenceNumberGet: %w", err)
			}

			switch v := res.(type) {
			case *api.AuthenticationOperationStatusResponse:
				code := v.GetStatus().Code
				switch code {
				case 100: // w toku – kolejna pętla
					continue
				case 200: // gotowe
					log.Infof("%v+", v.GetStatus())
					return redeemTokens(ctx, cli)
				default:
					desc := v.GetStatus().Description
					return nil, fmt.Errorf("uwierzytelnianie zakończone kodem %d (%s)", code, desc)
				}

			case *api.ExceptionResponse:
				return nil, ksef.HandleAPIError(v)

			default:
				return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
			}
		}
	}
}

func (c *Facade) RefreshToken(ctx context.Context, refreshToken string) (api.TokenInfo, error) {

	cli, err := api.NewClient(
		c.env.BaseURL(),
		localStaticBearer{Token: refreshToken},
		api.WithClient(c.httpClient),
	)
	if err != nil {
		return api.TokenInfo{}, err
	}

	res, err := cli.APIV2AuthTokenRefreshPost(ctx)
	if err != nil {
		return api.TokenInfo{}, fmt.Errorf("APIV2AuthTokenRefreshPost: %w", err)
	}

	switch v := res.(type) {
	case *api.AuthenticationTokenRefreshResponse:
		return v.GetAccessToken(), nil

	// specyficzny wariant błędu bez treści (401)
	case *api.APIV2AuthTokenRefreshPostUnauthorized:
		return api.TokenInfo{}, ksef.ErrUnauthorized

	// generyczne błędy 4xx/5xx z ciałem ExceptionResponse
	case *api.ExceptionResponse:
		return api.TokenInfo{}, ksef.HandleAPIError(v)

	default:
		return api.TokenInfo{}, fmt.Errorf("nieoczekiwany wariant odpowiedzi (refresh): %T", v)
	}
}

func redeemTokens(ctx context.Context, cli *api.Client) (*api.AuthenticationTokensResponse, error) {
	res, err := cli.APIV2AuthTokenRedeemPost(ctx)
	if err != nil {
		return nil, fmt.Errorf("APIV2AuthTokenRedeemPost: %w", err)
	}

	switch v := res.(type) {
	case *api.AuthenticationTokensResponse:
		return v, nil

	// specyficzny wariant błędu bez treści (401)
	case *api.APIV2AuthTokenRedeemPostUnauthorized:
		return nil, ksef.ErrUnauthorized

	case *api.ExceptionResponse:
		return nil, ksef.HandleAPIError(v)

	default:
		return nil, ksef.HandelOtherApiError(v)
	}
}
