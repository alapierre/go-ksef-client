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
	auth          TokenRefresher
	authenticator FullAuthenticator

	// Przechowywane tokenów per NIP
	mu    sync.Mutex
	cache map[string]*nipTokens

	onTokenUpdate TokenUpdateCallback

	// o ile wcześniej przed wygaśnięciem spróbować odświeżyć
	refreshSkew time.Duration
}

type nipTokens struct {
	accessToken  string
	accessExp    time.Time
	refreshToken string
	refreshExp   time.Time
}

// TokenUpdate opisuje zmianę tokenów zapisaną w TokenProviderze.
type TokenUpdate struct {
	NIP                 string
	AccessToken         api.TokenInfo
	RefreshToken        api.TokenInfo
	AccessTokenChanged  bool
	RefreshTokenChanged bool
}

// TokenUpdateCallback jest wywoływany po odświeżeniu access tokena lub refresh tokena.
type TokenUpdateCallback func(ctx context.Context, update TokenUpdate) error

type TokenProviderOption func(*TokenProvider)

// WithTokenUpdateCallback ustawia callback wywoływany po zmianie tokenów.
func WithTokenUpdateCallback(callback TokenUpdateCallback) TokenProviderOption {
	return func(p *TokenProvider) {
		p.onTokenUpdate = callback
	}
}

type pendingTokenUpdate struct {
	callback TokenUpdateCallback
	update   TokenUpdate
}

// NewTokenProvider tworzy provider bez wstępnego logowania; pełne uwierzytelnienie nastąpi on-demand
// przy pierwszym żądaniu dla danego NIP w Bearer().
func NewTokenProvider(auth TokenRefresher, authenticator FullAuthenticator, opts ...TokenProviderOption) *TokenProvider {
	p := &TokenProvider{
		auth:          auth,
		authenticator: authenticator,
		cache:         make(map[string]*nipTokens),
		refreshSkew:   30 * time.Second, // bufor bezpieczeństwa
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// SetTokenUpdateCallback ustawia lub czyści callback wywoływany po zmianie tokenów.
func (p *TokenProvider) SetTokenUpdateCallback(callback TokenUpdateCallback) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onTokenUpdate = callback
}

// SeedTokens zapisuje w providerze znaną parę access/refresh tokenów dla NIP.
// Dzięki temu Bearer() użyje access tokena, jeśli jest nadal ważny, albo spróbuje odświeżyć
// go przez refresh token przed przejściem do pełnego uwierzytelnienia.
func (p *TokenProvider) SeedTokens(ctx context.Context, accessToken api.TokenInfo, refreshToken api.TokenInfo) error {
	nip, ok := NipFromContext(ctx)
	if !ok || nip == "" {
		return ErrNoNip
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.cache[nip] = &nipTokens{
		accessToken:  accessToken.Token,
		accessExp:    accessToken.GetValidUntil().UTC(),
		refreshToken: refreshToken.Token,
		refreshExp:   refreshToken.GetValidUntil().UTC(),
	}

	return nil
}

// Bearer spełnia interfejs api.SecuritySource.
// Dla NIP z ctx zwraca ważny access token; gdy brak lub zaraz wygaśnie – odświeża.
// Jeżeli refresh token jest nieważny lub brak – wykonuje pełne uwierzytelnienie.
func (p *TokenProvider) Bearer(ctx context.Context, _ api.OperationName) (api.Bearer, error) {

	nip, ok := NipFromContext(ctx)
	if !ok || nip == "" {
		return api.Bearer{}, ErrNoNip
	}

	// wymuszenie pełnej autoryzacji
	if IsForceAuth(ctx) {
		logger.Debug("TokenProvider: Force auth requested")
		p.mu.Lock()
		bearer, update, err := p.fullAuthLocked(ctx)
		p.mu.Unlock()
		if err != nil {
			return api.Bearer{}, err
		}
		if err := update.notify(ctx); err != nil {
			return api.Bearer{}, err
		}
		return bearer, nil
	}

	// szybka ścieżka bez blokady
	if token, ok := p.currentIfValid(nip); ok {
		logger.Debug("TokenProvider: Found valid token in cache, returning it immediately")
		return api.Bearer{Token: token}, nil
	}

	// ścieżka z odświeżeniem / pełnym uwierzytelnieniem
	p.mu.Lock()

	// podwójne sprawdzenie po złapaniu blokady
	if token, ok := p.currentIfValidLocked(nip); ok {
		p.mu.Unlock()
		return api.Bearer{Token: token}, nil
	}

	// pobierz wpis dla NIP
	entry, found := p.cache[nip]
	if !found {
		// brak – pełne uwierzytelnienie
		logger.Debug("TokenProvider: No entry for context NIP, performing full authentication")
		bearer, update, err := p.fullAuthLocked(ctx)
		p.mu.Unlock()
		if err != nil {
			return api.Bearer{}, err
		}
		if err := update.notify(ctx); err != nil {
			return api.Bearer{}, err
		}
		return bearer, nil
	}

	// czy refresh token jest nadal ważny?
	if entry.refreshToken != "" && p.isTokenValid(entry.refreshExp) {
		// spróbuj odświeżyć access token
		logger.Debug("TokenProvider: Refresh token is valid, trying to refresh access token")

		var err error
		var update pendingTokenUpdate
		if update, err = p.refreshAccessTokenLocked(ctx); err == nil {
			token := p.cache[nip].accessToken
			p.mu.Unlock()
			if err := update.notify(ctx); err != nil {
				return api.Bearer{}, err
			}
			return api.Bearer{Token: token}, nil
		}
		// jeśli refresh nie powiódł się, spróbuj pełnego uwierzytelnienia
		logger.Debugf("TokenProvider: Refresh failed: %v, performing full authentication", err)
		bearer, update, err := p.fullAuthLocked(ctx)
		p.mu.Unlock()
		if err != nil {
			return api.Bearer{}, err
		}
		if err := update.notify(ctx); err != nil {
			return api.Bearer{}, err
		}
		return bearer, nil
	}

	// refresh token brak lub wygasł -> pełne uwierzytelnienie
	logger.Debug("All others options failed, finally performing full authentication")
	bearer, update, err := p.fullAuthLocked(ctx)
	p.mu.Unlock()
	if err != nil {
		return api.Bearer{}, err
	}
	if err := update.notify(ctx); err != nil {
		return api.Bearer{}, err
	}
	return bearer, nil
}

// Invalidate usuwa tokeny z cache dla NIP pobranego z kontekstu.
// Użyj tego np. po zmianie tokena używanego do pełnej autentykacji.
func (p *TokenProvider) Invalidate(ctx context.Context) error {
	nip, ok := NipFromContext(ctx)
	if !ok || nip == "" {
		return ErrNoNip
	}
	p.mu.Lock()
	delete(p.cache, nip)
	p.mu.Unlock()
	return nil
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

func (p *TokenProvider) refreshAccessTokenLocked(ctx context.Context) (pendingTokenUpdate, error) {

	nip, ok := NipFromContext(ctx)
	if !ok || nip == "" {
		return pendingTokenUpdate{}, ErrNoNip
	}

	entry, ok := p.cache[nip]
	if !ok || entry.refreshToken == "" {
		return pendingTokenUpdate{}, ErrNoRefreshToken
	}

	ti, err := p.auth.RefreshToken(ctx, entry.refreshToken)
	if err != nil {
		return pendingTokenUpdate{}, err
	}

	entry.accessToken = ti.Token
	entry.accessExp = ti.GetValidUntil().UTC()
	return pendingTokenUpdate{
		callback: p.onTokenUpdate,
		update: TokenUpdate{
			NIP: nip,
			AccessToken: api.TokenInfo{
				Token:      entry.accessToken,
				ValidUntil: entry.accessExp,
			},
			RefreshToken: api.TokenInfo{
				Token:      entry.refreshToken,
				ValidUntil: entry.refreshExp,
			},
			AccessTokenChanged: true,
		},
	}, nil
}

func (p *TokenProvider) fullAuthLocked(ctx context.Context) (api.Bearer, pendingTokenUpdate, error) {

	nip, ok := NipFromContext(ctx)
	if !ok || nip == "" {
		return api.Bearer{}, pendingTokenUpdate{}, ErrNoNip
	}

	logger.Debug("TokenProvider: Performing full authentication - calling authenticator func")
	tokens, err := p.authenticator(ctx)
	if err != nil {
		return api.Bearer{}, pendingTokenUpdate{}, err
	}
	at := tokens.GetAccessToken()
	rt := tokens.GetRefreshToken()
	p.cache[nip] = &nipTokens{
		accessToken:  at.Token,
		accessExp:    at.GetValidUntil().UTC(),
		refreshToken: rt.Token,
		refreshExp:   rt.GetValidUntil().UTC(),
	}
	logger.Debug("TokenProvider: Full authentication completed, tokens cached")
	return api.Bearer{Token: at.Token}, pendingTokenUpdate{
		callback: p.onTokenUpdate,
		update: TokenUpdate{
			NIP:                 nip,
			AccessToken:         at,
			RefreshToken:        rt,
			AccessTokenChanged:  true,
			RefreshTokenChanged: true,
		},
	}, nil
}

func (u pendingTokenUpdate) notify(ctx context.Context) error {
	if u.callback == nil {
		return nil
	}
	return u.callback(ctx, u.update)
}

// ErrNoRefreshToken sygnalizuje brak refresh tokena w źródle.
var ErrNoRefreshToken = errors.New("no refresh token available")

type FullAuthenticator func(ctx context.Context) (*api.AuthenticationTokensResponse, error)
