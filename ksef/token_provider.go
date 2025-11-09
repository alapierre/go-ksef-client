package ksef

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

// TokenProvider implementuje api.SecuritySource z automatycznym odświeżaniem access tokena.
type TokenProvider struct {
	auth *AuthFacade

	// przechowywane tokeny
	mu           sync.Mutex
	accessToken  string
	accessExp    time.Time
	refreshToken string

	// o ile wcześniej przed wygaśnięciem spróbować odświeżyć
	refreshSkew time.Duration
}

// NewTokenProvider tworzy źródło tokenów na bazie fasady AuthFacade
// tokens — odpowiedź z redeem zawierająca parę access/refresh
func NewTokenProvider(auth *AuthFacade, tokens *api.AuthenticationTokensResponse) *TokenProvider {
	at := tokens.GetAccessToken()
	rt := tokens.GetRefreshToken()

	expAt := at.GetValidUntil().UTC()

	return &TokenProvider{
		auth:         auth,
		accessToken:  at.Token,
		accessExp:    expAt,
		refreshToken: rt.Token,
		refreshSkew:  30 * time.Second, // bufor bezpieczeństwa
	}
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
