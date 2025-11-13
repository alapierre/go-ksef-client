package ksef

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
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

func (s *EncryptionService) encryptWithUsage(plaintext []byte, pubKey *rsa.PublicKey) ([]byte, error) {

	encrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("błąd szyfrowania RSA-OAEP: %w", err)
	}
	return encrypted, nil
}

// EncryptKsefToken szyfruje token KSeF + timestamp kluczem tokenowym
func (s *EncryptionService) EncryptKsefToken(ctx context.Context, ksefToken string, timestamp time.Time) ([]byte, error) {

	pubKey, err := s.GetPublicKeyFor(ctx, api.PublicKeyCertificateUsageKsefTokenEncryption)
	if err != nil {
		return nil, fmt.Errorf("nie można pobrać klucza publicznego (token): %w", err)
	}
	timestampMs := timestamp.UnixMilli()
	payload := fmt.Sprintf("%s|%d", ksefToken, timestampMs)
	return s.encryptWithUsage([]byte(payload), pubKey)
}

// EncryptSymmetricKey szyfruje klucz symetryczny faktury kluczem o Usage=SymmetricKeyEncryption
func (s *EncryptionService) EncryptSymmetricKey(ctx context.Context, symmetricKey []byte) ([]byte, error) {
	pubKey, err := s.GetPublicKeyFor(ctx, api.PublicKeyCertificateUsageSymmetricKeyEncryption)
	if err != nil {
		return nil, fmt.Errorf("nie można pobrać klucza publicznego (sym): %w", err)
	}
	return s.encryptWithUsage([]byte(symmetricKey), pubKey)
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

// EncryptBytesWithAES256CBCPKCS7 szyfruje content, używając AES-256-CBC z PKCS#7.
func EncryptBytesWithAES256CBCPKCS7(content, key, iv []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("nieprawidłowa długość klucza: %d, oczekiwano 32 bajty (AES-256)", len(key))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("nieprawidłowa długość IV: %d, oczekiwano %d", len(iv), aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("NewCipher: %w", err)
	}

	padded := pkcs7Pad(content, aes.BlockSize)
	out := make([]byte, len(padded))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out, padded)
	return out, nil
}

func pkcs7Pad(src []byte, blockSize int) []byte {
	padLen := blockSize - (len(src) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	return append(src, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

// EncryptFileAESCBCPKCS5 szyfruje plik wejściowy do wyjściowego (AES-256-CBC, PKCS5/7).
// Plik wyjściowy jest nadpisywany, jeśli istnieje.
func EncryptFileAESCBCPKCS5(inPath, outPath string, key, iv []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("klucz musi mieć 32 bajty (AES-256), ma %d", len(key))
	}
	if len(iv) != aes.BlockSize {
		return fmt.Errorf("IV musi mieć %d bajtów, ma %d", aes.BlockSize, len(iv))
	}

	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer func() {
		_ = out.Sync()
		_ = out.Close()
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("NewCipher: %w", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)

	// Bufor wielokrotności rozmiaru bloku (np. 64 KiB)
	const chunk = 64 * 1024
	buf := make([]byte, chunk)
	var carry []byte // ewentualny niedomiar dopełniany przy kolejnym czytaniu

	for {
		n, rErr := in.Read(buf)
		if n > 0 {
			data := append(carry, buf[:n]...)
			// Ile pełnych bloków możemy zaszyfrować teraz?
			fullLen := (len(data) / aes.BlockSize) * aes.BlockSize
			// Zostaw ostatni niepełny (albo zero) do carry
			toEnc := data[:fullLen]
			carry = data[fullLen:]

			if len(toEnc) > 0 {
				if err := encryptAndWriteCBC(out, mode, toEnc); err != nil {
					return fmt.Errorf("write encrypted: %w", err)
				}
			}
		}
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			return fmt.Errorf("read input: %w", rErr)
		}
	}

	// Dodaj PKCS#5/7 padding do ostatniego fragmentu (carry)
	padLen := aes.BlockSize - (len(carry) % aes.BlockSize)
	if padLen == 0 {
		padLen = aes.BlockSize
	}
	for i := 0; i < padLen; i++ {
		carry = append(carry, byte(padLen))
	}
	// Teraz carry ma pełną liczbę bloków
	if err := encryptAndWriteCBC(out, mode, carry); err != nil {
		return fmt.Errorf("write final encrypted: %w", err)
	}

	return nil
}

func encryptAndWriteCBC(w io.Writer, mode cipher.BlockMode, src []byte) error {
	if len(src)%mode.BlockSize() != 0 {
		return fmt.Errorf("długość danych (%d) nie jest wielokrotnością rozmiaru bloku (%d)", len(src), mode.BlockSize())
	}
	dst := make([]byte, len(src))
	mode.CryptBlocks(dst, src)
	_, err := w.Write(dst)
	return err
}

// DecryptBytesAESCBCPKCS5 odszyfrowuje bufor AES-256-CBC z PKCS5/7.
func DecryptBytesAESCBCPKCS5(ciphertext, key, iv []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("klucz musi mieć 32 bajty (AES-256), ma %d", len(key))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV musi mieć %d bajtów, ma %d", aes.BlockSize, len(iv))
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("dane nie są wielokrotnością rozmiaru bloku")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("NewCipher: %w", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	plain := make([]byte, len(ciphertext))
	mode.CryptBlocks(plain, ciphertext)

	// PKCS7 unpad z walidacją
	if len(plain) == 0 {
		return nil, fmt.Errorf("puste dane po deszyfrowaniu")
	}
	pad := int(plain[len(plain)-1])
	if pad <= 0 || pad > aes.BlockSize || pad > len(plain) {
		return nil, fmt.Errorf("niepoprawny padding")
	}
	// sprawdź wszystkie bajty paddingu
	for i := 0; i < pad; i++ {
		if plain[len(plain)-1-i] != byte(pad) {
			return nil, fmt.Errorf("niepoprawny padding")
		}
	}
	return plain[:len(plain)-pad], nil
}

// DecryptFileAESCBCPKCS5 odszyfrowuje plik wejściowy do wyjściowego (AES-256-CBC, PKCS5/7).
// Plik wyjściowy jest nadpisywany, jeśli istnieje.
func DecryptFileAESCBCPKCS5(inPath, outPath string, key, iv []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("klucz musi mieć 32 bajty (AES-256), ma %d", len(key))
	}
	if len(iv) != aes.BlockSize {
		return fmt.Errorf("IV musi mieć %d bajtów, ma %d", aes.BlockSize, len(iv))
	}

	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	// jeśli błąd, usuń plik wynikowy
	defer func() {
		_ = out.Sync()
		_ = out.Close()
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("NewCipher: %w", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	const chunk = 64 * 1024
	if (chunk % aes.BlockSize) != 0 {
		return fmt.Errorf("chunk size must be multiple of block size")
	}
	buf := make([]byte, chunk)

	// Trzymamy poprzedni blok, aby na końcu móc zweryfikować i usunąć padding,
	// a wcześniej zapisać wszystkie wcześniejsze bloki bez buforowania całego pliku.
	var prev []byte

	writeDecrypted := func(b []byte) error {
		// b musi być wielokrotnością bloku
		if len(b)%aes.BlockSize != 0 {
			return fmt.Errorf("nieprawidłowa długość bloku do zapisu")
		}
		dst := make([]byte, len(b))
		mode.CryptBlocks(dst, b)
		_, err := out.Write(dst)
		return err
	}

	for {
		n, rErr := in.Read(buf)
		if n > 0 {
			chunkData := buf[:n]
			// jeśli mamy prev, dołącz go do początku i zachowaj ostatni blok
			if len(prev) > 0 {
				chunkData = append(prev, chunkData...)
				prev = nil
			}
			// jeśli długość nie jest wielokrotnością bloku, odetnij ostatni niepełny fragment do prev
			fullLen := (len(chunkData) / aes.BlockSize) * aes.BlockSize
			// Zostaw jeden blok na koniec do obsługi paddingu; ale tylko gdy nie EOF.
			// Nie możemy zapisywać ostatniego bloku od razu, bo nie wiemy, czy to ostatni blok całego pliku.
			if rErr != io.EOF {
				if fullLen >= aes.BlockSize {
					prev = append([]byte{}, chunkData[fullLen-aes.BlockSize:fullLen]...)
					fullLen -= aes.BlockSize
				}
			}
			toDec := chunkData[:fullLen]
			tail := chunkData[fullLen:]
			if len(toDec) > 0 {
				if err := writeDecrypted(toDec); err != nil {
					return fmt.Errorf("write decrypted: %w", err)
				}
			}
			// tail może być niepełnym blokiem — zachowaj
			if len(tail) > 0 {
				prev = append(prev, tail...)
			}
		}
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			return fmt.Errorf("read input: %w", rErr)
		}
	}

	// Na końcu prev powinno zawierać ostatni pełny blok szyfrogramu (z paddingiem).
	if len(prev) == 0 || len(prev)%aes.BlockSize != 0 {
		return fmt.Errorf("brak ostatniego bloku do usunięcia paddingu")
	}

	// Odszyfruj ostatni blok w pamięci, usuń padding i zapisz plain (bez paddingu).
	last := make([]byte, len(prev))
	mode.CryptBlocks(last, prev)

	if len(last) == 0 {
		return fmt.Errorf("puste dane po deszyfrowaniu")
	}
	pad := int(last[len(last)-1])
	if pad <= 0 || pad > aes.BlockSize || pad > len(last) {
		return fmt.Errorf("niepoprawny padding")
	}
	for i := 0; i < pad; i++ {
		if last[len(last)-1-i] != byte(pad) {
			return fmt.Errorf("niepoprawny padding")
		}
	}
	last = last[:len(last)-pad]

	if len(last) > 0 {
		if _, err := out.Write(last); err != nil {
			return fmt.Errorf("write final plaintext: %w", err)
		}
	}

	return nil
}
