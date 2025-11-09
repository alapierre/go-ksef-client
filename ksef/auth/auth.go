package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	api "github.com/alapierre/go-ksef-client/ksef/api"
)

// LoginByKsefToken wywołanie "startu" z tokenem KSeF (zwraca ID procesu/status).
type LoginByKsefToken func(ctx context.Context, ksefToken string) (loginID string, err error)

// PollLogin cykliczne pytanie "czy gotowe?" dla loginID.
type PollLogin func(ctx context.Context, loginID string) (ready bool, err error)

// ExchangeForTokens - finalny krok: pobiera access/refresh + TTL.
type ExchangeForTokens func(ctx context.Context, loginID string) (access, refresh string, expiresInSec int, err error)

type KsefTokenFlowProvider struct {
	Login    LoginByKsefToken
	Poll     PollLogin
	Exchange ExchangeForTokens

	KsefToken string // statyczny token KSeF (z aplikacji podatnika / przypisany do NIP)
}

func (p *KsefTokenFlowProvider) Start(ctx context.Context) (string, error) {
	return p.Login(ctx, p.KsefToken)
}

type TokenManager struct {
	prov *KsefTokenFlowProvider

	noAuthOps map[api.OperationName]struct{}
	clockSkew time.Duration

	mu          sync.Mutex
	accessToken string
	refreshTok  string
	expiresAt   time.Time
}

func NewTokenManager(prov *KsefTokenFlowProvider, noAuthOps []api.OperationName, clockSkew time.Duration) *TokenManager {
	m := &TokenManager{
		prov:      prov,
		noAuthOps: map[api.OperationName]struct{}{},
		clockSkew: clockSkew,
	}
	for _, op := range noAuthOps {
		m.noAuthOps[op] = struct{}{}
	}
	return m
}

// implementuje api.SecuritySource (ogen)
func (m *TokenManager) Bearer(ctx context.Context, op api.OperationName) (api.Bearer, error) {
	// dla operacji logowania po tokenie KSeF -> brak Authorization
	if _, skip := m.noAuthOps[op]; skip {
		return api.Bearer{}, nil
	}
	// dla reszty -> zapewnij ważny bearer
	if err := m.ensureValid(ctx); err != nil {
		return api.Bearer{}, err
	}
	return api.Bearer{Token: m.accessToken}, nil
}

func (m *TokenManager) ensureValid(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.accessToken != "" && time.Until(m.expiresAt) > m.clockSkew {
		return nil
	}

	// pełny flow: login → poll → exchange (tu nie ma refresh endpointu — w razie czego łatwo dodać)
	loginID, err := m.prov.Start(ctx)
	if err != nil {
		return err
	}

	// polling z prostym backoffem (1s, 2s, 2s, 2s...) max 60s
	deadline := time.Now().Add(60 * time.Second)
	delay := 1 * time.Second

	for {
		if time.Now().After(deadline) {
			return errors.New("KSeF login polling timeout")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			ready, err := m.prov.Poll(ctx, loginID)
			if err != nil {
				return err
			}
			if ready {
				access, refresh, ttl, err := m.prov.Exchange(ctx, loginID)
				if err != nil {
					return err
				}
				if ttl <= 0 {
					ttl = 300
				}
				m.accessToken = access
				m.refreshTok = refresh
				m.expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
				return nil
			}
			// prosty backoff
			if delay < 2*time.Second {
				delay = 2 * time.Second
			}
		}
	}
}
