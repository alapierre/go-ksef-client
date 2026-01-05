package qr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/alapierre/go-ksef-client/ksef"
	"github.com/sirupsen/logrus"
)

var logger = logrus.WithField("component", "qr")

type ContextIdentifierType string

const (
	CtxNip        ContextIdentifierType = "Nip"
	CtxInternalId ContextIdentifierType = "InternalId"
	CtxNipVatUe   ContextIdentifierType = "NipVatUe"
)

// ====== KOD I ======

// GenerateVerificationLink buduje link w formacie:
// https://{qr-env}/client-app/invoice/{NIP}/{DD-MM-YYYY}/{Base64URL(SHA256(xml)) no padding}
func GenerateVerificationLink(env ksef.Environment, nip string, issueDate time.Time, invoiceXML []byte) (string, error) {
	baseQR, err := QRBaseURL(env.BaseURL())
	if err != nil {
		return "", err
	}

	normalizedNip, err := normalizeAndValidateNip(nip)
	if err != nil {
		return "", err
	}

	date := issueDate.Format("02-01-2006") // dd-MM-yyyy
	hash := computeInvoiceHashBase64URL(invoiceXML)

	return fmt.Sprintf("%s/client-app/invoice/%s/%s/%s", trimTrailingSlash(baseQR), normalizedNip, date, hash), nil
}

// ====== KOD II ======

// GenerateCertificateVerificationLink buduje link KOD II i podpisuje ciąg: "{host}{path}"
// np. "qr-test.ksef.mf.gov.pl/client-app/certificate/Nip/...."
func GenerateCertificateVerificationLink(
	env ksef.Environment,
	ctxType ContextIdentifierType,
	ctxValue string,
	sellerNip string,
	certSerial string,
	privateKey crypto.PrivateKey, // *rsa.PrivateKey lub *ecdsa.PrivateKey
	invoiceHash []byte, // SHA-256(XML) jako bajty (32)
) (string, error) {

	if len(invoiceHash) == 0 {
		return "", fmt.Errorf("invoiceHash is empty")
	}

	baseQR, err := QRBaseURL(env.BaseURL())

	if err != nil {
		return "", err
	}

	logger.Debugf("baseQR: %s", baseQR)
	baseQR = trimTrailingSlash(baseQR)

	normalizedNip, err := normalizeAndValidateNip(sellerNip)
	if err != nil {
		return "", err
	}

	invoiceHashB64 := base64.RawURLEncoding.EncodeToString(invoiceHash)

	// Ścieżka bez podpisu
	path := fmt.Sprintf(
		"/certificate/%s/%s/%s/%s/%s",
		string(ctxType),
		ctxValue,
		normalizedNip,
		certSerial,
		invoiceHashB64,
	)

	// Dane do podpisu: host + path (bez schematu)
	hostPathToSign, err := hostPlusPath(baseQR, path)
	if err != nil {
		return "", err
	}

	logger.Debugf("TO_SIGN: %s", hostPathToSign)

	sigB64, err := computeSignedHashBase64URL(hostPathToSign, privateKey)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s%s/%s", baseQR, path, sigB64), nil
}

// ====== URL / ENV helpers ======

// QRBaseURL mapuje BaseURL() na host qr-...
func QRBaseURL(base string) (string, error) {
	if strings.TrimSpace(base) == "" {
		return "", fmt.Errorf("base URL is empty")
	}

	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("base URL must include scheme and host, got: %q", base)
	}

	host := u.Host

	host = strings.Replace(host, "api-", "qr-", 1)
	host = strings.Replace(host, "api.", "qr.", 1)

	u.Host = host
	u.Path = ""     // baza bez ścieżki
	u.RawQuery = "" // bez query
	u.Fragment = ""

	return u.String(), nil
}

// ExtractCertSerial zwraca serial certyfikatu w HEX (UPPERCASE),
// analogicznie do Twojej metody Java extractCertSerial().
func ExtractCertSerial(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("cert is nil")
	}
	if cert.SerialNumber == nil {
		return "", errors.New("cert.SerialNumber is nil")
	}

	b := cert.SerialNumber.Bytes() // dodatnia wartość bez znaku

	serial := strings.ToUpper(hex.EncodeToString(b))
	if serial == "" {
		return "", errors.New("empty serial after encoding")
	}
	return serial, nil
}

func LoadCertificateFromFile(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cert file: %w", err)
	}
	return LoadCertificate(b)
}

func LoadCertificate(certBytes []byte) (*x509.Certificate, error) {
	// PEM?
	if block, _ := pem.Decode(certBytes); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block: %s", block.Type)
		}
		certBytes = block.Bytes
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, errors.New("parsed cert is nil")
	}
	return cert, nil
}

func hostPlusPath(baseURL string, path string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("base URL has no host: %q", baseURL)
	}
	// path ma zaczynać się od /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return u.Host + path, nil
}

func trimTrailingSlash(s string) string {
	return strings.TrimRight(s, "/")
}

// ====== Crypto helpers ======

func computeInvoiceHashBase64URL(invoiceXML []byte) string {
	sum := sha256.Sum256(invoiceXML)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// computeSignedHashBase64URL podpisuje SHA-256(host+path) RSA-PSS (salt=32) lub ECDSA.
// Zwraca Base64URL bez paddingu.
func computeSignedHashBase64URL(dataToSign string, key crypto.PrivateKey) (string, error) {
	data := []byte(dataToSign)
	digest := sha256.Sum256(data)

	switch k := key.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPSS(rand.Reader, k, crypto.SHA256, digest[:], &rsa.PSSOptions{
			SaltLength: 32,
			Hash:       crypto.SHA256,
		})
		if err != nil {
			return "", fmt.Errorf("rsa-pss sign failed: %w", err)
		}
		return base64.RawURLEncoding.EncodeToString(sig), nil

	case *ecdsa.PrivateKey:
		// ECDSA w Go zwróci DER (ASN.1) – to jest typowy format podpisu ECDSA
		sigDER, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
		if err != nil {
			return "", fmt.Errorf("ecdsa sign failed: %w", err)
		}
		return base64.RawURLEncoding.EncodeToString(sigDER), nil

	default:
		return "", fmt.Errorf("unsupported private key type: %T (expected *rsa.PrivateKey or *ecdsa.PrivateKey)", key)
	}
}

// ====== NIP ======

var nipDigitsRe = regexp.MustCompile(`\D+`)

func normalizeAndValidateNip(nip string) (string, error) {
	digits := nipDigitsRe.ReplaceAllString(nip, "")
	if len(digits) != 10 {
		return "", errors.New("NIP must contain exactly 10 digits")
	}
	return digits, nil
}
