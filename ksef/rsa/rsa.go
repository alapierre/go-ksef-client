package rsa

import (
	rsa2 "crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/alapierre/go-ksef-client/ksef/api"
)

func ParseRSAPubFromCert(c api.PublicKeyCertificate) (*rsa2.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(c.Certificate)
	if err != nil {
		return nil, fmt.Errorf("decode cert: %w", err)
	}
	xc, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse x509: %w", err)
	}
	rsaPub, ok := xc.PublicKey.(*rsa2.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cert nie zawiera klucza RSA (typ: %T)", xc.PublicKey)
	}
	return rsaPub, nil
}

func ParseRSAPubFromB64Cert(certB64 string) (*rsa2.PublicKey, time.Time, error) {
	der, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("decode cert: %w", err)
	}
	xc, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse x509: %w", err)
	}
	rsaPub, ok := xc.PublicKey.(*rsa2.PublicKey)
	if !ok {
		return nil, time.Time{}, fmt.Errorf("cert nie zawiera klucza RSA (typ: %T)", xc.PublicKey)
	}
	return rsaPub, xc.NotAfter, nil
}
