package ksef

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
	log "github.com/sirupsen/logrus"
)

type DefaultKsefClient struct {
	raw        *api.Client
	env        Environment
	httpClient *http.Client
}

// NewDefaultKsefClient Konstruktor fasady. Security może być nil (dla operacji bez autoryzacji).
func NewDefaultKsefClient(env Environment, httpClient *http.Client, security api.SecuritySource) (*DefaultKsefClient, error) {
	cli, err := api.NewClient(
		env.BaseURL(),
		security,
		api.WithClient(httpClient),
	)
	if err != nil {
		return nil, err
	}
	return &DefaultKsefClient{raw: cli, env: env, httpClient: httpClient}, nil
}

func (c *DefaultKsefClient) GetChallenge(ctx context.Context) (*api.AuthenticationChallengeResponse, error) {
	res, err := c.raw.APIV2AuthChallengePost(ctx)
	if err != nil {
		return nil, err
	}

	switch v := res.(type) {
	case *api.AuthenticationChallengeResponse:
		return v, nil

		// generyczna obsługa błędów (4xx/5xx):
	case interface{ GetValue() *api.ExceptionResponse }:
		return nil, handleAPIError(v)

	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

func (c *DefaultKsefClient) AuthWithToken(ctx context.Context, challenge api.Challenge, nip Nip, encryptedTokenBytes []byte) (*api.AuthenticationInitResponse, error) {

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
	case interface{ GetValue() *api.ExceptionResponse }:
		return nil, handleAPIError(v)
	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}
}

// prosty bearer do tego calla
type localStaticBearer struct{ Token string }

func (b localStaticBearer) Bearer(ctx context.Context, _ api.OperationName) (api.Bearer, error) {
	return api.Bearer{Token: b.Token}, nil
}

// AuthWaitAndRedeem Polluje status aż do 200 lub do ctx.Done(). Interwał czekania kontrolowany parametrem pollEvery.
func (c *DefaultKsefClient) AuthWaitAndRedeem(ctx context.Context, authResp *api.AuthenticationInitResponse, pollEvery time.Duration) (*api.AuthenticationTokensResponse, error) {
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

			case interface{ GetValue() *api.ExceptionResponse }:
				return nil, handleAPIError(v)

			default:
				return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
			}
		}
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
		return nil, fmt.Errorf("redeem: 401 Unauthorized")

	// generyczne błędy 4xx/5xx z ciałem ExceptionResponse
	case interface{ GetValue() *api.ExceptionResponse }:
		return nil, handleAPIError(v)

	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi (redeem): %T", v)
	}
}

// handleAPIError obsługuje generyczne błędy API (4xx/5xx)
func handleAPIError(response interface{}) error {
	v, ok := response.(interface{ GetValue() *api.ExceptionResponse })
	if !ok {
		return fmt.Errorf("nieoczekiwany typ odpowiedzi: %T", response)
	}

	ex := v.GetValue()

	// Stwórz podstawowy komunikat błędu
	errorMsg := fmt.Sprintf("błąd API: %s", ex.GetException().Value)

	// Sprawdź czy mamy listę szczegółów błędów
	if details, ok := ex.GetException().Value.ExceptionDetailList.Get(); ok && len(details) > 0 {
		errorMsg += "\nSzczegóły:"
		for i, detail := range details {
			errorMsg += fmt.Sprintf("\n  %d: %+v", i+1, detail)
		}
	}

	return fmt.Errorf(errorMsg)
}
