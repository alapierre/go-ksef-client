package ksef

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
	log "github.com/sirupsen/logrus"
)

// TokenProvider implementuje api.SecuritySource z automatycznym odświeżaniem access tokena.
type TokenProvider struct {
	auth          TokenRefresher
	authenticator FullAuthenticator

	// Przechowywane tokenów per NIP
	mu    sync.Mutex
	cache map[string]*nipTokens

	// o ile wcześniej przed wygaśnięciem spróbować odświeżyć
	refreshSkew time.Duration
}

type nipTokens struct {
	accessToken  string
	accessExp    time.Time
	refreshToken string
	refreshExp   time.Time
}

// NewTokenProvider tworzy provider bez wstępnego logowania; pełne uwierzytelnienie nastąpi on-demand
// przy pierwszym żądaniu dla danego NIP w Bearer().
func NewTokenProvider(auth TokenRefresher, authenticator FullAuthenticator) *TokenProvider {
	return &TokenProvider{
		auth:          auth,
		authenticator: authenticator,
		cache:         make(map[string]*nipTokens),
		refreshSkew:   30 * time.Second, // bufor bezpieczeństwa
	}
}

// Bearer spełnia interfejs api.SecuritySource.
// Dla NIP z ctx zwraca ważny access token; gdy brak lub zaraz wygaśnie – odświeża.
// Jeżeli refresh token jest nieważny lub brak – wykonuje pełne uwierzytelnienie.
func (p *TokenProvider) Bearer(ctx context.Context, _ api.OperationName) (api.Bearer, error) {

	nip, ok := NipFromContext(ctx)
	if !ok || nip == "" {
		return api.Bearer{}, ErrNoNip
	}

	// szybka ścieżka bez blokady
	if token, ok := p.currentIfValid(nip); ok {
		return api.Bearer{Token: token}, nil
	}

	// ścieżka z odświeżeniem / pełnym uwierzytelnieniem
	p.mu.Lock()
	defer p.mu.Unlock()

	// podwójne sprawdzenie po złapaniu blokady
	if token, ok := p.currentIfValidLocked(nip); ok {
		return api.Bearer{Token: token}, nil
	}

	// pobierz wpis dla NIP
	entry, found := p.cache[nip]
	if !found {
		// brak – pełne uwierzytelnienie
		log.Debug("TokenProvider: No entry for context NIP, performing full authentication")
		return p.fullAuthLocked(ctx)
	}

	// czy refresh token jest nadal ważny?
	if entry.refreshToken != "" && p.isTokenValid(entry.refreshExp) {
		// spróbuj odświeżyć access token
		log.Debug("TokenProvider: Refresh token expired or empty, trying to refresh access token")

		var err error
		if err = p.refreshAccessTokenLocked(ctx); err == nil {
			return api.Bearer{Token: p.cache[nip].accessToken}, nil
		}
		// jeśli refresh nie powiódł się, spróbuj pełnego uwierzytelnienia
		log.Debugf("TokenProvider: Refresh failed: %v, performing full authentication", err)
		return p.fullAuthLocked(ctx)
	}

	// refresh token brak lub wygasł -> pełne uwierzytelnienie
	log.Debug("All others options failed, finally performing full authentication")
	return p.fullAuthLocked(ctx)
}

// Zakłada blokadę i sprawdza - deleguje do currentIfValidLocked()
func (p *TokenProvider) currentIfValid(nip string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.currentIfValidLocked(nip)
}

// Nie blokuje, zakłada, że blokadę założyła metoda wywołująca
func (p *TokenProvider) currentIfValidLocked(nip string) (string, bool) {
	entry, ok := p.cache[nip]
	if !ok || entry.accessToken == "" {
		return "", false
	}
	// brak daty ważności -> wymuś odświeżenie
	if entry.accessExp.IsZero() {
		return "", false
	}
	// porównuj w UTC z marginesem
	now := time.Now().UTC()
	if entry.accessExp.Sub(now) <= p.refreshSkew {
		return "", false
	}
	return entry.accessToken, true
}

func (p *TokenProvider) isTokenValid(exp time.Time) bool {
	if exp.IsZero() {
		return false
	}
	now := time.Now().UTC()
	return exp.Sub(now) > p.refreshSkew
}

func (p *TokenProvider) refreshAccessTokenLocked(ctx context.Context) error {

	nip, ok := NipFromContext(ctx)
	if !ok || nip == "" {
		return ErrNoNip
	}

	entry, ok := p.cache[nip]
	if !ok || entry.refreshToken == "" {
		return ErrNoRefreshToken
	}

	ti, err := p.auth.RefreshToken(ctx, entry.refreshToken)
	if err != nil {
		return err
	}

	entry.accessToken = ti.Token
	entry.accessExp = ti.GetValidUntil().UTC()
	return nil
}

func (p *TokenProvider) fullAuthLocked(ctx context.Context) (api.Bearer, error) {

	nip, ok := NipFromContext(ctx)
	if !ok || nip == "" {
		return api.Bearer{}, ErrNoNip
	}

	log.Debug("TokenProvider: Performing full authentication - calling authenticator func")
	tokens, err := p.authenticator(ctx)
	if err != nil {
		return api.Bearer{}, err
	}
	at := tokens.GetAccessToken()
	rt := tokens.GetRefreshToken()
	p.cache[nip] = &nipTokens{
		accessToken:  at.Token,
		accessExp:    at.GetValidUntil().UTC(),
		refreshToken: rt.Token,
		refreshExp:   rt.GetValidUntil().UTC(),
	}
	log.Debug("TokenProvider: Full authentication completed, tokens cached")
	return api.Bearer{Token: at.Token}, nil
}

// ErrNoRefreshToken sygnalizuje brak refresh tokena w źródle.
var ErrNoRefreshToken = errors.New("no refresh token available")

type FullAuthenticator func(ctx context.Context) (*api.AuthenticationTokensResponse, error)
