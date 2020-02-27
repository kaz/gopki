package authority

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"github.com/kaz/gopki/keyfactory"
)

type (
	Authority struct {
		key    crypto.Signer
		keyfac keyfactory.Factory
	}
)

func New(key crypto.Signer, keyfac keyfactory.Factory) *Authority {
	return &Authority{key, keyfac}
}

func (a *Authority) GenReq(commonName string) (*x509.CertificateRequest, crypto.Signer, error) {
	key, err := a.keyfac.NewKey()
	if err != nil {
		return nil, nil, fmt.Errorf("a.keyfac.NewKey failed: %w", err)
	}

	reqTemp := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	rawReq, err := x509.CreateCertificateRequest(rand.Reader, reqTemp, key)
	if err != nil {
		return nil, nil, fmt.Errorf("x509.CreateCertificateRequest failed: %w", err)
	}

	req, err := x509.ParseCertificateRequest(rawReq)
	if err != nil {
		return nil, nil, fmt.Errorf("x509.ParseCertificateRequest failed: %w", err)
	}

	return req, key, nil
}
