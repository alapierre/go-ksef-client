package ksef

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
	rsa2 "github.com/alapierre/go-ksef-client/ksef/rsa"
)

type EncryptionService struct {
	cli *api.Client

	mu sync.RWMutex

	// klucz do szyfrowania tokenów (Usage=KsefTokenEncryption)
	tokenPub         *rsa.PublicKey
	tokenPublicKeyID []byte
	tokenValidTo     time.Time

	// klucz do szyfrowania klucza symetrycznego faktury (Usage=SymmetricKeyEncryption)
	symKeyPub         *rsa.PublicKey
	symKeyPublicKeyID []byte
	symKeyValidTo     time.Time

	lastFetch time.Time

	// How long before expiration should the keys be refreshed (safety margin)
	refreshSkew time.Duration
}

type Option func(*EncryptionService)

func WithRefreshSkew(d time.Duration) Option {
	return func(s *EncryptionService) { s.refreshSkew = d }
}

type PreloadedKeys struct {
	TokenCertBase64      string
	SymmetricCertBase64  string
	TokenRSAPub          *rsa.PublicKey
	SymmetricRSAPub      *rsa.PublicKey
	TokenPublicKeyID     []byte
	SymmetricPublicKeyID []byte
	TokenValidTo         time.Time
	SymmetricValidTo     time.Time
}

type EncryptedPayload struct {
	Data        []byte
	PublicKeyID []byte
}

func WithPreloadedKeys(pk PreloadedKeys) Option {
	return func(s *EncryptionService) {
		if pk.TokenRSAPub == nil && pk.TokenCertBase64 != "" {
			if rsaPub, validTo, err := rsa2.ParseRSAPubFromB64Cert(pk.TokenCertBase64); err == nil {
				pk.TokenRSAPub = rsaPub
				if pk.TokenValidTo.IsZero() {
					pk.TokenValidTo = validTo
				}
			}
		}
		if pk.SymmetricRSAPub == nil && pk.SymmetricCertBase64 != "" {
			if rsaPub, validTo, err := rsa2.ParseRSAPubFromB64Cert(pk.SymmetricCertBase64); err == nil {
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
			s.tokenPublicKeyID = cloneBytes(pk.TokenPublicKeyID)
			s.tokenValidTo = pk.TokenValidTo
		}
		if pk.SymmetricRSAPub != nil {
			s.symKeyPub = pk.SymmetricRSAPub
			s.symKeyPublicKeyID = cloneBytes(pk.SymmetricPublicKeyID)
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

func (s *EncryptionService) encryptWithUsage(plaintext []byte, pubKey *rsa.PublicKey) ([]byte, error) {

	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("błąd szyfrowania RSA-OAEP: %w", err)
	}
	return encrypted, nil
}

// Deprecated: Use EncryptKsefTokenWithKeyID instead.
// EncryptKsefToken szyfruje token KSeF + timestamp kluczem tokenowym.
func (s *EncryptionService) EncryptKsefToken(ctx context.Context, ksefToken string, timestamp time.Time) ([]byte, error) {
	encrypted, err := s.EncryptKsefTokenWithKeyID(ctx, ksefToken, timestamp)
	if err != nil {
		return nil, err
	}
	return encrypted.Data, nil
}

// EncryptKsefTokenWithKeyID szyfruje token KSeF + timestamp i zwraca identyfikator użytego klucza.
func (s *EncryptionService) EncryptKsefTokenWithKeyID(ctx context.Context, ksefToken string, timestamp time.Time) (EncryptedPayload, error) {

	pubKey, publicKeyID, err := s.GetPublicKeyWithIDFor(ctx, api.PublicKeyCertificateUsageKsefTokenEncryption)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("nie można pobrać klucza publicznego (token): %w", err)
	}
	timestampMs := timestamp.UnixMilli()
	payload := fmt.Sprintf("%s|%d", ksefToken, timestampMs)
	encrypted, err := s.encryptWithUsage([]byte(payload), pubKey)
	if err != nil {
		return EncryptedPayload{}, err
	}
	return EncryptedPayload{Data: encrypted, PublicKeyID: publicKeyID}, nil
}

// Deprecated: Use EncryptSymmetricKeyWithKeyID instead.
// EncryptSymmetricKey szyfruje klucz symetryczny faktury kluczem o Usage=SymmetricKeyEncryption.
func (s *EncryptionService) EncryptSymmetricKey(ctx context.Context, symmetricKey []byte) ([]byte, error) {
	encrypted, err := s.EncryptSymmetricKeyWithKeyID(ctx, symmetricKey)
	if err != nil {
		return nil, err
	}
	return encrypted.Data, nil
}

// EncryptSymmetricKeyWithKeyID szyfruje klucz symetryczny i zwraca identyfikator użytego klucza.
func (s *EncryptionService) EncryptSymmetricKeyWithKeyID(ctx context.Context, symmetricKey []byte) (EncryptedPayload, error) {
	pubKey, publicKeyID, err := s.GetPublicKeyWithIDFor(ctx, api.PublicKeyCertificateUsageSymmetricKeyEncryption)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("nie można pobrać klucza publicznego (sym): %w", err)
	}
	encrypted, err := s.encryptWithUsage([]byte(symmetricKey), pubKey)
	if err != nil {
		return EncryptedPayload{}, err
	}
	return EncryptedPayload{Data: encrypted, PublicKeyID: publicKeyID}, nil
}

// BuildEncryptionInfo szyfruje klucz symetryczny i uzupełnia publicKeyId w modelu żądania.
func (s *EncryptionService) BuildEncryptionInfo(ctx context.Context, symmetricKey, iv []byte) (api.EncryptionInfo, error) {
	encrypted, err := s.EncryptSymmetricKeyWithKeyID(ctx, symmetricKey)
	if err != nil {
		return api.EncryptionInfo{}, err
	}
	return api.EncryptionInfo{
		EncryptedSymmetricKey: encrypted.Data,
		InitializationVector:  iv,
		PublicKeyId:           optPublicKeyID(encrypted.PublicKeyID),
	}, nil
}

// Deprecated: use GetPublicKeyWithIDFor instead
// GetPublicKeyFor zwraca klucz publiczny dla wskazanego Usage.
func (s *EncryptionService) GetPublicKeyFor(ctx context.Context, usage api.PublicKeyCertificateUsage) (*rsa.PublicKey, error) {
	pub, _, err := s.GetPublicKeyWithIDFor(ctx, usage)
	return pub, err
}

// GetPublicKeyWithIDFor zwraca klucz publiczny i publicKeyId dla wskazanego Usage.
func (s *EncryptionService) GetPublicKeyWithIDFor(ctx context.Context, usage api.PublicKeyCertificateUsage) (*rsa.PublicKey, []byte, error) {
	s.mu.RLock()
	var pub *rsa.PublicKey
	var publicKeyID []byte
	var validTo time.Time
	switch usage {
	case api.PublicKeyCertificateUsageKsefTokenEncryption:
		pub, publicKeyID, validTo = s.tokenPub, cloneBytes(s.tokenPublicKeyID), s.tokenValidTo
	case api.PublicKeyCertificateUsageSymmetricKeyEncryption:
		pub, publicKeyID, validTo = s.symKeyPub, cloneBytes(s.symKeyPublicKeyID), s.symKeyValidTo
	default:
		s.mu.RUnlock()
		return nil, nil, fmt.Errorf("nieobsługiwany usage: %v", usage)
	}
	s.mu.RUnlock()

	if pub != nil && time.Until(validTo) > s.refreshSkew {
		return pub, publicKeyID, nil
	}
	if err := s.fetchAndSelect(ctx, false); err != nil {
		return nil, nil, err
	}

	// Po odświeżeniu – bez kolejnego switcha: ponownie odczytaj docelowy klucz
	s.mu.RLock()
	defer s.mu.RUnlock()
	if usage == api.PublicKeyCertificateUsageKsefTokenEncryption {
		if s.tokenPub == nil {
			return nil, nil, fmt.Errorf("brak ważnego certyfikatu RSA z Usage=KsefTokenEncryption")
		}
		return s.tokenPub, cloneBytes(s.tokenPublicKeyID), nil
	}
	// usage == SymmetricKeyEncryption (inne przypadki odfiltrowane wyżej)
	if s.symKeyPub == nil {
		return nil, nil, fmt.Errorf("brak ważnego certyfikatu RSA z Usage=SymmetricKeyEncryption")
	}
	return s.symKeyPub, cloneBytes(s.symKeyPublicKeyID), nil
}

// ForceRefresh wymusza odświeżenie cache obu kluczy; nie zwraca klucza.
// Po wywołaniu użyj GetPublicKeyWithIDFor(...) lub metod szyfrujących.
func (s *EncryptionService) ForceRefresh(ctx context.Context) error {
	logger.Debug("Force refreshing encryption keys")
	return s.fetchAndSelect(ctx, true)
}

// fetchAndSelect pobiera listę certyfikatów i wybiera najnowsze ważne dla obu Usage
func (s *EncryptionService) fetchAndSelect(ctx context.Context, force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	logger.Debug(" Fetching and selecting encryption keys")
	// ktoś mógł już odświeżyć w międzyczasie
	if !force &&
		s.tokenPub != nil && time.Until(s.tokenValidTo) > s.refreshSkew &&
		s.symKeyPub != nil && time.Until(s.symKeyValidTo) > s.refreshSkew {
		logger.Debug("Refresh skipped: keys already valid")
		return nil
	}

	now := time.Now()
	res, err := s.cli.SecurityPublicKeyCertificatesGet(ctx)
	if err != nil {
		return err
	}

	var certs []api.PublicKeyCertificate
	switch v := res.(type) {
	case *api.SecurityPublicKeyCertificatesGetOKApplicationJSON:
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
				logger.Debug("Found token cert")
			}
			if u == api.PublicKeyCertificateUsageSymmetricKeyEncryption {
				hasSym = true
				logger.Debug("Found sym cert")
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
		if rsaPub, err := rsa2.ParseRSAPubFromCert(*chosenToken); err == nil {
			s.tokenPub = rsaPub
			s.tokenPublicKeyID = cloneBytes(chosenToken.PublicKeyId)
			s.tokenValidTo = chosenToken.ValidTo
			logger.Debugf("Token cert parsed, expires at %s", s.tokenValidTo)
		} else {
			return fmt.Errorf("parse token cert: %w", err)
		}
	} else {
		s.tokenPub = nil
		s.tokenPublicKeyID = nil
		s.tokenValidTo = time.Time{}
	}
	if chosenSym != nil {
		if rsaPub, err := rsa2.ParseRSAPubFromCert(*chosenSym); err == nil {
			s.symKeyPub = rsaPub
			s.symKeyPublicKeyID = cloneBytes(chosenSym.PublicKeyId)
			s.symKeyValidTo = chosenSym.ValidTo
			logger.Debugf("Symmetric cert parsed, expires at %s", s.symKeyValidTo)
		} else {
			return fmt.Errorf("parse symmetric cert: %w", err)
		}
	} else {
		s.symKeyPub = nil
		s.symKeyPublicKeyID = nil
		s.symKeyValidTo = time.Time{}
	}

	// tokenowy jest wymagany dla ścieżek uwierzytelnienia tokenem
	if s.tokenPub == nil {
		return fmt.Errorf("brak ważnego certyfikatu RSA z Usage=KsefTokenEncryption")
	}

	s.lastFetch = now
	return nil
}

func optPublicKeyID(publicKeyID []byte) api.OptNilByte {
	if len(publicKeyID) == 0 {
		return api.OptNilByte{}
	}
	return api.NewOptNilByte(cloneBytes(publicKeyID))
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	return append([]byte(nil), in...)
}

func firstPublicKeyID(publicKeyID [][]byte) []byte {
	if len(publicKeyID) == 0 {
		return nil
	}
	return publicKeyID[0]
}
