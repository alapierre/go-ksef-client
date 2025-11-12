package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

// TokenProvider implementuje api.SecuritySource z automatycznym odświeżaniem access tokena.
type TokenProvider struct {
	auth          TokenRefresher
	authenticator FullAuthenticator

	// przechowywane tokeny
	mu           sync.Mutex
	accessToken  string
	accessExp    time.Time
	refreshToken string

	// o ile wcześniej przed wygaśnięciem spróbować odświeżyć
	refreshSkew time.Duration
}

// NewTokenProvider creates a TokenProvider by invoking the provided full authenticator and using the Facade for Bearer token handling.
func NewTokenProvider(ctx context.Context, auth TokenRefresher, authenticator FullAuthenticator) (*TokenProvider, error) {

	tokens, err := authenticator(ctx)
	if err != nil {
		return nil, err
	}

	at := tokens.GetAccessToken()
	rt := tokens.GetRefreshToken()

	expAt := at.GetValidUntil().UTC()

	return &TokenProvider{
		auth:          auth,
		authenticator: authenticator,
		accessToken:   at.Token,
		accessExp:     expAt,
		refreshToken:  rt.Token,
		refreshSkew:   30 * time.Second, // bufor bezpieczeństwa
	}, nil
}

// Bearer spełnia interfejs api.SecuritySource.
// Zwraca ważny access token; gdy wygasł lub zaraz wygaśnie – odświeża go.
func (p *TokenProvider) Bearer(ctx context.Context, _ api.OperationName) (api.Bearer, error) {
	// szybka ścieżka bez blokady
	if token, ok := p.currentIfValid(); ok {
		return api.Bearer{Token: token}, nil
	}

	// ścieżka z odświeżeniem
	p.mu.Lock()
	defer p.mu.Unlock()

	// podwójne sprawdzenie po złapaniu blokady
	if token, ok := p.currentIfValidLocked(); ok {
		return api.Bearer{Token: token}, nil
	}

	// brak ważnego access tokena -> odśwież
	newAT, err := p.refreshAccessToken(ctx)
	if err != nil {
		return api.Bearer{}, err
	}
	return api.Bearer{Token: newAT}, nil
}

func (p *TokenProvider) currentIfValid() (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentIfValidLocked()
}

func (p *TokenProvider) currentIfValidLocked() (string, bool) {
	if p.accessToken == "" {
		return "", false
	}
	// brak daty ważności -> wymuś odświeżenie
	if p.accessExp.IsZero() {
		return "", false
	}
	// porównuj w UTC z marginesem
	now := time.Now().UTC()
	if p.accessExp.Sub(now) <= p.refreshSkew {
		return "", false
	}
	return p.accessToken, true
}

func (p *TokenProvider) refreshAccessToken(ctx context.Context) (string, error) {
	if p.refreshToken == "" {
		return "", ErrNoRefreshToken
	}

	ti, err := p.auth.RefreshToken(ctx, p.refreshToken)
	if err != nil {
		return "", err
	}

	p.accessToken = ti.Token
	p.accessExp = ti.GetValidUntil()
	return p.accessToken, nil
}

// ErrNoRefreshToken sygnalizuje brak refresh tokena w źródle.
var ErrNoRefreshToken = errors.New("no refresh token available")

type FullAuthenticator func(ctx context.Context) (*api.AuthenticationTokensResponse, error)
