package ksef

import (
	"bytes"
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
	result, _, err := c.GetChallengeWithMetadata(ctx)
	return result, err
}

// GetChallengeWithMetadata is GetChallenge with successful response headers.
func (c *AuthFacade) GetChallengeWithMetadata(ctx context.Context) (*api.AuthenticationChallengeResponse, ResponseMetadata, error) {
	res, err := c.raw.AuthChallengePost(ctx)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}

	switch v := res.(type) {
	case *api.AuthenticationChallengeResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

// AuthWithToken starts token-based authentication with an already encrypted token.
// Pass publicKeyID when the encrypted token was created with EncryptKsefTokenWithKeyID.
func (c *AuthFacade) AuthWithToken(ctx context.Context, challenge api.Challenge, encryptedTokenBytes []byte, publicKeyID ...[]byte) (*api.AuthenticationInitResponse, error) {
	result, _, err := c.AuthWithTokenWithMetadata(ctx, challenge, encryptedTokenBytes, publicKeyID...)
	return result, err
}

// AuthWithTokenWithMetadata is AuthWithToken with successful response headers.
func (c *AuthFacade) AuthWithTokenWithMetadata(ctx context.Context, challenge api.Challenge, encryptedTokenBytes []byte, publicKeyID ...[]byte) (*api.AuthenticationInitResponse, ResponseMetadata, error) {

	nip, ok := NipFromContext(ctx)
	if !ok || nip == "" {
		return nil, ResponseMetadata{}, ErrNoNip
	}

	if len(publicKeyID) > 1 {
		return nil, ResponseMetadata{}, fmt.Errorf("only one publicKeyID is supported")
	}

	req := api.InitTokenAuthenticationRequest{
		Challenge: challenge,
		ContextIdentifier: api.AuthenticationContextIdentifier{
			Type:  api.AuthenticationContextIdentifierTypeNip,
			Value: nip,
		},
		EncryptedToken:      encryptedTokenBytes,
		PublicKeyId:         optPublicKeyID(firstPublicKeyID(publicKeyID)),
		AuthorizationPolicy: api.OptNilAuthorizationPolicy{},
	}

	optReq := api.NewOptInitTokenAuthenticationRequest(req)

	res, err := c.raw.AuthKsefTokenPost(ctx, optReq)
	if err != nil {
		return nil, ResponseMetadata{}, fmt.Errorf("APIV2AuthKsefTokenPost: %w", err)
	}

	switch v := res.(type) {
	case *api.AuthenticationInitResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

func (c *AuthFacade) AuthWithXades(ctx context.Context, signedXml []byte) (*api.AuthenticationInitResponse, error) {
	result, _, err := c.AuthWithXadesWithMetadata(ctx, signedXml)
	return result, err
}

// AuthWithXadesWithMetadata is AuthWithXades with successful response headers.
func (c *AuthFacade) AuthWithXadesWithMetadata(ctx context.Context, signedXml []byte) (*api.AuthenticationInitResponse, ResponseMetadata, error) {

	req := api.AuthXadesSignaturePostReq{
		Data: bytes.NewReader(signedXml),
	}

	params := api.AuthXadesSignaturePostParams{
		VerifyCertificateChain: api.NewOptBool(false),
	}

	res, err := c.raw.AuthXadesSignaturePost(ctx, req, params)

	if err != nil {
		return nil, ResponseMetadata{}, fmt.Errorf("APIV2AuthKsefTokenPost: %w", err)
	}

	switch v := res.(type) {
	case *api.AuthenticationInitResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}

}

// AuthWaitAndRedeem Polluje status aż do 200 lub do ctx.Done(). Interwał czekania kontrolowany parametrem pollEvery.
func (c *AuthFacade) AuthWaitAndRedeem(ctx context.Context, authResp *api.AuthenticationInitResponse, pollEvery time.Duration) (*api.AuthenticationTokensResponse, error) {
	result, _, err := c.AuthWaitAndRedeemWithMetadata(ctx, authResp, pollEvery)
	return result, err
}

// AuthWaitAndRedeemWithMetadata is AuthWaitAndRedeem with successful response headers.
// Metadata describes the final token redemption response.
func (c *AuthFacade) AuthWaitAndRedeemWithMetadata(ctx context.Context, authResp *api.AuthenticationInitResponse, pollEvery time.Duration) (*api.AuthenticationTokensResponse, ResponseMetadata, error) {
	if authResp == nil {
		return nil, ResponseMetadata{}, fmt.Errorf("authResponse is nil")
	}

	cli, err := api.NewClient(
		c.env.BaseURL(),
		localStaticBearer{Token: authResp.GetAuthenticationToken().Token},
		api.WithClient(c.httpClient),
	)
	if err != nil {
		return nil, ResponseMetadata{}, err
	}

	params := api.AuthReferenceNumberGetParams{
		ReferenceNumber: authResp.GetReferenceNumber(),
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ResponseMetadata{}, ctx.Err()

		case <-time.After(pollEvery):
			res, err := cli.AuthReferenceNumberGet(ctx, params)
			if err != nil {
				return nil, ResponseMetadata{}, fmt.Errorf("APIV2AuthReferenceNumberGet: %w", err)
			}

			switch v := res.(type) {
			case *api.AuthenticationOperationStatusResponseHeaders:
				code := v.Response.GetStatus().Code
				switch code {
				case 100: // w toku – kolejna pętla
					continue
				case 200: // gotowe
					logger.Infof("%+v", v.Response.GetStatus())
					return redeemTokensWithMetadata(ctx, cli)
				default:
					desc := v.Response.GetStatus().Description
					return nil, ResponseMetadata{}, fmt.Errorf("uwierzytelnianie zakończone kodem %d (%s)", code, desc)
				}

			default:
				return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
			}
		}
	}
}

func (c *AuthFacade) RefreshToken(ctx context.Context, refreshToken string) (api.TokenInfo, error) {
	result, _, err := c.RefreshTokenWithMetadata(ctx, refreshToken)
	return result, err
}

// RefreshTokenWithMetadata is RefreshToken with successful response headers.
func (c *AuthFacade) RefreshTokenWithMetadata(ctx context.Context, refreshToken string) (api.TokenInfo, ResponseMetadata, error) {

	cli, err := api.NewClient(
		c.env.BaseURL(),
		localStaticBearer{Token: refreshToken},
		api.WithClient(c.httpClient),
	)
	if err != nil {
		return api.TokenInfo{}, ResponseMetadata{}, err
	}

	res, err := cli.AuthTokenRefreshPost(ctx)
	if err != nil {
		return api.TokenInfo{}, ResponseMetadata{}, fmt.Errorf("APIV2AuthTokenRefreshPost: %w", err)
	}

	switch v := res.(type) {
	case *api.AuthenticationTokenRefreshResponseHeaders:
		return api.TokenInfo(v.Response.GetAccessToken()), responseMetadata(v), nil
	default:
		return api.TokenInfo{}, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

func (c *AuthFacade) CloseAuthSession(ctx context.Context, token string) error {
	_, err := c.CloseAuthSessionWithMetadata(ctx, token)
	return err
}

// CloseAuthSessionWithMetadata is CloseAuthSession with successful response headers.
func (c *AuthFacade) CloseAuthSessionWithMetadata(ctx context.Context, token string) (ResponseMetadata, error) {
	cli, err := api.NewClient(
		c.env.BaseURL(),
		localStaticBearer{Token: token},
		api.WithClient(c.httpClient),
	)
	if err != nil {
		return ResponseMetadata{}, err
	}

	res, err := cli.AuthSessionsCurrentDelete(ctx)
	if err != nil {
		return ResponseMetadata{}, fmt.Errorf("APIV2AuthSessionsCurrentDelete: %w", err)
	}

	switch v := res.(type) {
	case *api.AuthSessionsCurrentDeleteNoContent:
		return responseMetadata(v), nil
	default:
		return ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}

func redeemTokens(ctx context.Context, cli *api.Client) (*api.AuthenticationTokensResponse, error) {
	result, _, err := redeemTokensWithMetadata(ctx, cli)
	return result, err
}

// redeemTokensWithMetadata is redeemTokens with successful response headers.
func redeemTokensWithMetadata(ctx context.Context, cli *api.Client) (*api.AuthenticationTokensResponse, ResponseMetadata, error) {
	res, err := cli.AuthTokenRedeemPost(ctx)
	if err != nil {
		return nil, ResponseMetadata{}, fmt.Errorf("APIV2AuthTokenRedeemPost: %w", err)
	}

	switch v := res.(type) {
	case *api.AuthenticationTokensResponseHeaders:
		return &v.Response, responseMetadata(v), nil
	default:
		return nil, ResponseMetadata{}, responseAPIError(v, http.StatusBadRequest)
	}
}
