package ksef

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

type AuthFacade struct {
	raw        *api.Client
	env        Environment
	httpClient *http.Client
}

// Prosty bearer do obsługi pośredniej autoryzacji
type localStaticBearer struct{ Token string }

func (b localStaticBearer) Bearer(ctx context.Context, _ api.OperationName) (api.Bearer, error) {
	return api.Bearer{Token: b.Token}, nil
}

// NewAuthFacade Konstruktor fasady autoryzacyjnej.
func NewAuthFacade(env Environment, httpClient *http.Client) (*AuthFacade, error) {
	cli, err := api.NewClient(
		env.BaseURL(),
		nil,
		api.WithClient(httpClient),
	)
	if err != nil {
		return nil, err
	}
	return &AuthFacade{raw: cli, env: env, httpClient: httpClient}, nil
}

func (c *AuthFacade) GetChallenge(ctx context.Context) (*api.AuthenticationChallengeResponse, error) {
	res, err := c.raw.AuthChallengePost(ctx)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.AuthenticationChallengeResponse:
		return v, nil

		// generyczna obsługa błędów (4xx/5xx):
	case *api.ExceptionResponse:
		return nil, HandleAPIError(v)

	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

func (c *AuthFacade) AuthWithToken(ctx context.Context, challenge api.Challenge, encryptedTokenBytes []byte) (*api.AuthenticationInitResponse, error) {

	nip, ok := NipFromContext(ctx)
	if !ok || nip == "" {
		return nil, ErrNoNip
	}

	req := api.InitTokenAuthenticationRequest{
		Challenge: challenge,
		ContextIdentifier: api.AuthenticationContextIdentifier{
			Type:  api.AuthenticationContextIdentifierTypeNip,
			Value: nip,
		},
		EncryptedToken:      encryptedTokenBytes,
		AuthorizationPolicy: api.OptNilAuthorizationPolicy{},
	}

	optReq := api.NewOptInitTokenAuthenticationRequest(req)

	res, err := c.raw.AuthKsefTokenPost(ctx, optReq)
	if err != nil {
		return nil, fmt.Errorf("APIV2AuthKsefTokenPost: %w", err)
	}

	switch v := res.(type) {
	case *api.AuthenticationInitResponse:
		return v, nil
	case *api.ExceptionResponse:
		return nil, HandleAPIError(v)
	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

// AuthWaitAndRedeem Polluje status aż do 200 lub do ctx.Done(). Interwał czekania kontrolowany parametrem pollEvery.
func (c *AuthFacade) AuthWaitAndRedeem(ctx context.Context, authResp *api.AuthenticationInitResponse, pollEvery time.Duration) (*api.AuthenticationTokensResponse, error) {
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

	params := api.AuthReferenceNumberGetParams{
		ReferenceNumber: authResp.GetReferenceNumber(),
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		case <-time.After(pollEvery):
			res, err := cli.AuthReferenceNumberGet(ctx, params)
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
					logger.Infof("%v+", v.GetStatus())
					return redeemTokens(ctx, cli)
				default:
					desc := v.GetStatus().Description
					return nil, fmt.Errorf("uwierzytelnianie zakończone kodem %d (%s)", code, desc)
				}

			case *api.ExceptionResponse:
				return nil, HandleAPIError(v)

			default:
				return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
			}
		}
	}
}

func (c *AuthFacade) RefreshToken(ctx context.Context, refreshToken string) (api.TokenInfo, error) {

	cli, err := api.NewClient(
		c.env.BaseURL(),
		localStaticBearer{Token: refreshToken},
		api.WithClient(c.httpClient),
	)
	if err != nil {
		return api.TokenInfo{}, err
	}

	res, err := cli.AuthTokenRefreshPost(ctx)
	if err != nil {
		return api.TokenInfo{}, fmt.Errorf("APIV2AuthTokenRefreshPost: %w", err)
	}

	switch v := res.(type) {
	case *api.AuthenticationTokenRefreshResponse:
		return v.GetAccessToken(), nil

	// specyficzny wariant błędu bez treści (401)
	case *api.AuthTokenRefreshPostUnauthorized:
		return api.TokenInfo{}, ErrUnauthorized

	// generyczne błędy 4xx/5xx z ciałem ExceptionResponse
	case *api.ExceptionResponse:
		return api.TokenInfo{}, HandleAPIError(v)

	default:
		return api.TokenInfo{}, fmt.Errorf("nieoczekiwany wariant odpowiedzi (refresh): %T", v)
	}
}

func redeemTokens(ctx context.Context, cli *api.Client) (*api.AuthenticationTokensResponse, error) {
	res, err := cli.AuthTokenRedeemPost(ctx)
	if err != nil {
		return nil, fmt.Errorf("APIV2AuthTokenRedeemPost: %w", err)
	}

	switch v := res.(type) {
	case *api.AuthenticationTokensResponse:
		return v, nil

	// specyficzny wariant błędu bez treści (401)
	case *api.AuthTokenRedeemPostUnauthorized:
		return nil, ErrUnauthorized

	case *api.ExceptionResponse:
		return nil, HandleAPIError(v)

	default:
		return nil, HandelOtherApiError(v)
	}
}
