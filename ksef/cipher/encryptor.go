package cipher

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/alapierre/go-ksef-client/ksef"
	"github.com/alapierre/go-ksef-client/ksef/api"
)

type EncryptionService struct {
	cli *api.Client

	mu        sync.RWMutex
	pub       *rsa.PublicKey
	validTo   time.Time
	lastFetch time.Time

	// ile wcześniej odświeżyć klucz zanim wygaśnie (margines bezpieczeństwa)
	refreshSkew time.Duration
}

type Option func(*EncryptionService)

func WithRefreshSkew(d time.Duration) Option {
	return func(s *EncryptionService) { s.refreshSkew = d }
}

func NewEncryptionService(env ksef.Environment, httpClient *http.Client, opts ...Option) (*EncryptionService, error) {
	cli, err := api.NewClient(
		env.BaseURL(),
		nil, // nie potrzebujemy autoryzacji do pobierania certyfikatów publicznych
		api.WithClient(httpClient),
	)
	if err != nil {
		return nil, err
	}

	s := &EncryptionService{
		cli:         cli,
		refreshSkew: 2 * time.Minute,
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Encrypt szyfruje dane, używając RSA-OAEP z SHA-256 i aktualnego klucza publicznego KSeF
func (s *EncryptionService) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	pubKey, err := s.GetPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("nie można pobrać klucza publicznego: %w", err)
	}

	// Szyfrowanie RSA-OAEP z SHA-256 (zgodnie z wymaganiami KSeF)
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("błąd szyfrowania RSA-OAEP: %w", err)
	}

	return encrypted, nil
}

// EncryptToBase64 szyfruje dane i zwraca je zakodowane w Base64
func (s *EncryptionService) EncryptToBase64(ctx context.Context, plaintext []byte) (string, error) {
	encrypted, err := s.Encrypt(ctx, plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// EncryptString szyfruje string i zwraca zakodowany w Base64
func (s *EncryptionService) EncryptString(ctx context.Context, plaintext string) (string, error) {
	return s.EncryptToBase64(ctx, []byte(plaintext))
}

// EncryptKsefToken szyfruje token KSeF wraz z timestampem i zwraca surowe bajty (nie base64).
func (s *EncryptionService) EncryptKsefToken(ctx context.Context, ksefToken string, timestamp time.Time) ([]byte, error) {
	timestampMs := timestamp.UnixMilli()
	payload := fmt.Sprintf("%s|%d", ksefToken, timestampMs)
	return s.Encrypt(ctx, []byte(payload))
}

func (s *EncryptionService) GetPublicKey(ctx context.Context) (*rsa.PublicKey, error) {
	// szybka ścieżka: mamy ważny klucz?
	s.mu.RLock()
	pub := s.pub
	validTo := s.validTo
	s.mu.RUnlock()

	if pub != nil && time.Until(validTo) > s.refreshSkew {
		return pub, nil
	}

	// wolna ścieżka: pobierz świeży
	return s.fetchAndSelect(ctx)
}

// Wymuszenie odświeżenia cache (np. po 400/403 z KSeF)
func (s *EncryptionService) ForceRefresh(ctx context.Context) (*rsa.PublicKey, error) {
	return s.fetchAndSelect(ctx)
}

func (s *EncryptionService) fetchAndSelect(ctx context.Context) (*rsa.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// ktoś mógł już odświeżyć w międzyczasie
	if s.pub != nil && time.Until(s.validTo) > s.refreshSkew {
		return s.pub, nil
	}

	now := time.Now()
	res, err := s.cli.APIV2SecurityPublicKeyCertificatesGet(ctx)
	if err != nil {
		return nil, err
	}

	var certs []api.PublicKeyCertificate

	switch v := res.(type) {
	case *api.APIV2SecurityPublicKeyCertificatesGetOKApplicationJSON:
		certs = *v

	default:
		return nil, fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}

	var chosen *api.PublicKeyCertificate
	for i := range certs {
		c := certs[i]
		if now.Before(c.ValidFrom) || now.After(c.ValidTo) {
			continue
		}
		usageOK := false
		for _, u := range c.Usage {
			if u == api.PublicKeyCertificateUsageKsefTokenEncryption {
				usageOK = true
				break
			}
		}
		if !usageOK {
			continue
		}
		if chosen == nil || c.ValidFrom.After(chosen.ValidFrom) {
			chosen = &c
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("brak ważnego certyfikatu RSA z Usage=KsefTokenEncryption")
	}

	der, err := base64.StdEncoding.DecodeString(chosen.Certificate)
	if err != nil {
		return nil, fmt.Errorf("decode cert: %w", err)
	}
	xc, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse x509: %w", err)
	}
	rsaPub, ok := xc.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cert nie zawiera klucza RSA (typ: %T)", xc.PublicKey)
	}

	// zapisz do cache
	s.pub = rsaPub
	s.validTo = chosen.ValidTo
	s.lastFetch = now
	return s.pub, nil
}
