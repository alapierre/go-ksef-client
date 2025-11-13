package ksef

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

	"github.com/alapierre/go-ksef-client/ksef/api"
	log "github.com/sirupsen/logrus"
)

type EncryptionService struct {
	cli *api.Client

	mu sync.RWMutex

	// klucz do szyfrowania tokenów (Usage=KsefTokenEncryption)
	tokenPub     *rsa.PublicKey
	tokenValidTo time.Time

	// klucz do szyfrowania klucza symetrycznego faktury (Usage=SymmetricKeyEncryption)
	symKeyPub     *rsa.PublicKey
	symKeyValidTo time.Time

	lastFetch time.Time

	// ile wcześniej odświeżyć klucze zanim wygasną (margines bezpieczeństwa)
	refreshSkew time.Duration
}

type Option func(*EncryptionService)

func WithRefreshSkew(d time.Duration) Option {
	return func(s *EncryptionService) { s.refreshSkew = d }
}

type PreloadedKeys struct {
	TokenCertBase64     string
	SymmetricCertBase64 string
	TokenRSAPub         *rsa.PublicKey
	SymmetricRSAPub     *rsa.PublicKey
	TokenValidTo        time.Time
	SymmetricValidTo    time.Time
}

func WithPreloadedKeys(pk PreloadedKeys) Option {
	return func(s *EncryptionService) {
		if pk.TokenRSAPub == nil && pk.TokenCertBase64 != "" {
			if rsaPub, validTo, err := parseRSAPubFromB64Cert(pk.TokenCertBase64); err == nil {
				pk.TokenRSAPub = rsaPub
				if pk.TokenValidTo.IsZero() {
					pk.TokenValidTo = validTo
				}
			}
		}
		if pk.SymmetricRSAPub == nil && pk.SymmetricCertBase64 != "" {
			if rsaPub, validTo, err := parseRSAPubFromB64Cert(pk.SymmetricCertBase64); err == nil {
				pk.SymmetricRSAPub = rsaPub
				if pk.SymmetricValidTo.IsZero() {
					pk.SymmetricValidTo = validTo
				}
			}
		}

		s.mu.Lock()
		defer s.mu.Unlock()
		if pk.TokenRSAPub != nil {
			s.tokenPub = pk.TokenRSAPub
			s.tokenValidTo = pk.TokenValidTo
		}
		if pk.SymmetricRSAPub != nil {
			s.symKeyPub = pk.SymmetricRSAPub
			s.symKeyValidTo = pk.SymmetricValidTo
		}
	}
}

func NewEncryptionService(env Environment, httpClient *http.Client, opts ...Option) (*EncryptionService, error) {
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

// Encrypt szyfruje dane dla klucza tokenowego (RSA-OAEP SHA-256)
func (s *EncryptionService) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	pubKey, err := s.GetPublicKeyFor(ctx, api.PublicKeyCertificateUsageKsefTokenEncryption)
	if err != nil {
		return nil, fmt.Errorf("nie można pobrać klucza publicznego (token): %w", err)
	}
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("błąd szyfrowania RSA-OAEP: %w", err)
	}
	return encrypted, nil
}

// EncryptToBase64 szyfruje dane kluczem tokenowym i zwraca Base64
func (s *EncryptionService) EncryptToBase64(ctx context.Context, plaintext []byte) (string, error) {
	encrypted, err := s.Encrypt(ctx, plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// EncryptString szyfruje string kluczem tokenowym i zwraca Base64
func (s *EncryptionService) EncryptString(ctx context.Context, plaintext string) (string, error) {
	return s.EncryptToBase64(ctx, []byte(plaintext))
}

// EncryptKsefToken szyfruje token KSeF + timestamp kluczem tokenowym
func (s *EncryptionService) EncryptKsefToken(ctx context.Context, ksefToken string, timestamp time.Time) ([]byte, error) {
	timestampMs := timestamp.UnixMilli()
	payload := fmt.Sprintf("%s|%d", ksefToken, timestampMs)
	return s.Encrypt(ctx, []byte(payload))
}

// EncryptSymmetricKey szyfruje klucz symetryczny faktury kluczem o Usage=SymmetricKeyEncryption
func (s *EncryptionService) EncryptSymmetricKey(ctx context.Context, symmetricKey []byte) ([]byte, error) {
	pubKey, err := s.GetPublicKeyFor(ctx, api.PublicKeyCertificateUsageSymmetricKeyEncryption)
	if err != nil {
		return nil, fmt.Errorf("nie można pobrać klucza publicznego (sym): %w", err)
	}
	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, symmetricKey, nil)
	if err != nil {
		return nil, fmt.Errorf("błąd szyfrowania RSA-OAEP: %w", err)
	}
	return encrypted, nil
}

// GetPublicKeyFor zwraca klucz publiczny dla wskazanego Usage
func (s *EncryptionService) GetPublicKeyFor(ctx context.Context, usage api.PublicKeyCertificateUsage) (*rsa.PublicKey, error) {
	s.mu.RLock()
	var pub *rsa.PublicKey
	var validTo time.Time
	switch usage {
	case api.PublicKeyCertificateUsageKsefTokenEncryption:
		pub, validTo = s.tokenPub, s.tokenValidTo
	case api.PublicKeyCertificateUsageSymmetricKeyEncryption:
		pub, validTo = s.symKeyPub, s.symKeyValidTo
	default:
		s.mu.RUnlock()
		return nil, fmt.Errorf("nieobsługiwany usage: %v", usage)
	}
	s.mu.RUnlock()

	if pub != nil && time.Until(validTo) > s.refreshSkew {
		return pub, nil
	}
	if err := s.fetchAndSelect(ctx); err != nil {
		return nil, err
	}

	// Po odświeżeniu – bez kolejnego switcha: ponownie odczytaj docelowy klucz
	s.mu.RLock()
	defer s.mu.RUnlock()
	if usage == api.PublicKeyCertificateUsageKsefTokenEncryption {
		if s.tokenPub == nil {
			return nil, fmt.Errorf("brak ważnego certyfikatu RSA z Usage=KsefTokenEncryption")
		}
		return s.tokenPub, nil
	}
	// usage == SymmetricKeyEncryption (inne przypadki odfiltrowane wyżej)
	if s.symKeyPub == nil {
		return nil, fmt.Errorf("brak ważnego certyfikatu RSA z Usage=SymmetricKeyEncryption")
	}
	return s.symKeyPub, nil
}

// ForceRefresh wymusza odświeżenie cache obu kluczy; nie zwraca klucza.
// Po wywołaniu użyj GetPublicKeyFor(...) lub metod szyfrujących.
func (s *EncryptionService) ForceRefresh(ctx context.Context) error {
	log.Debug("Force refreshing encryption keys")
	return s.fetchAndSelect(ctx)
}

// fetchAndSelect pobiera listę certyfikatów i wybiera najnowsze ważne dla obu Usage
func (s *EncryptionService) fetchAndSelect(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Debug("Fetching and selecting encryption keys")
	// ktoś mógł już odświeżyć w międzyczasie
	if s.tokenPub != nil && time.Until(s.tokenValidTo) > s.refreshSkew &&
		s.symKeyPub != nil && time.Until(s.symKeyValidTo) > s.refreshSkew {
		log.Debug("Refresh skipped: keys already valid")
		return nil
	}

	now := time.Now()
	res, err := s.cli.APIV2SecurityPublicKeyCertificatesGet(ctx)
	if err != nil {
		return err
	}

	var certs []api.PublicKeyCertificate
	switch v := res.(type) {
	case *api.APIV2SecurityPublicKeyCertificatesGetOKApplicationJSON:
		certs = *v
	default:
		return fmt.Errorf("nieoczekiwany wariant odpowiedzi: %T", v)
	}

	var chosenToken *api.PublicKeyCertificate
	var chosenSym *api.PublicKeyCertificate

	for i := range certs {
		c := certs[i]
		if now.Before(c.ValidFrom) || now.After(c.ValidTo) {
			continue
		}
		hasToken := false
		hasSym := false
		for _, u := range c.Usage {
			if u == api.PublicKeyCertificateUsageKsefTokenEncryption {
				hasToken = true
				log.Debug("Found token cert")
			}
			if u == api.PublicKeyCertificateUsageSymmetricKeyEncryption {
				hasSym = true
				log.Debug("Found sym cert")
			}
		}
		if hasToken && (chosenToken == nil || c.ValidFrom.After(chosenToken.ValidFrom)) {
			tmp := c
			chosenToken = &tmp
		}
		if hasSym && (chosenSym == nil || c.ValidFrom.After(chosenSym.ValidFrom)) {
			tmp := c
			chosenSym = &tmp
		}
	}

	if chosenToken != nil {
		if rsaPub, err := parseRSAPubFromCert(*chosenToken); err == nil {
			s.tokenPub = rsaPub
			s.tokenValidTo = chosenToken.ValidTo
			log.Debugf("Token cert parsed, expires at %s", s.tokenValidTo)
		} else {
			return fmt.Errorf("parse token cert: %w", err)
		}
	}
	if chosenSym != nil {
		if rsaPub, err := parseRSAPubFromCert(*chosenSym); err == nil {
			s.symKeyPub = rsaPub
			s.symKeyValidTo = chosenSym.ValidTo
			log.Debugf("Symmetric cert parsed, expires at %s", s.symKeyValidTo)
		} else {
			return fmt.Errorf("parse symmetric cert: %w", err)
		}
	}

	// tokenowy jest wymagany dla ścieżek uwierzytelnienia tokenem
	if s.tokenPub == nil {
		return fmt.Errorf("brak ważnego certyfikatu RSA z Usage=KsefTokenEncryption")
	}

	s.lastFetch = now
	return nil
}

func parseRSAPubFromCert(c api.PublicKeyCertificate) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(c.Certificate)
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
	return rsaPub, nil
}

func parseRSAPubFromB64Cert(certB64 string) (*rsa.PublicKey, time.Time, error) {
	der, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("decode cert: %w", err)
	}
	xc, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse x509: %w", err)
	}
	rsaPub, ok := xc.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, time.Time{}, fmt.Errorf("cert nie zawiera klucza RSA (typ: %T)", xc.PublicKey)
	}
	return rsaPub, xc.NotAfter, nil
}

// GenerateRandom256BitsKey generuje losowy 256-bitowy klucz (32 bajty)
func GenerateRandom256BitsKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits = 32 bytes
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("błąd generowania losowego klucza: %w", err)
	}
	return key, nil
}

// GenerateRandom16BytesIv generuje losowy 16-bajtowy wektor inicjalizacji
func GenerateRandom16BytesIv() ([]byte, error) {
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("błąd generowania losowego IV: %w", err)
	}
	return iv, nil
}
