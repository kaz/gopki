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
		cert   *x509.Certificate
		key    crypto.Signer
		keyfac keyfactory.Factory
	}
)

func New(cert *x509.Certificate, key crypto.Signer, fac keyfactory.Factory) *Authority {
	return &Authority{cert, key, fac}
}
func NewEmpty(fac keyfactory.Factory) *Authority {
	return New(nil, nil, fac)
}
func NewFromRaw(rawCert, rawKey []byte, fac keyfactory.Factory) (*Authority, error) {
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate failed: %w", err)
	}

	key, err := keyfactory.Parse(rawKey)
	if err != nil {
		return nil, fmt.Errorf("keyfactory.Parse failed: %w", err)
	}

	return New(cert, key, fac), nil
}

func (a *Authority) BuildFull(certType CertificateType, commonName string) (*x509.Certificate, crypto.Signer, error) {
	req, key, err := a.GenReq(commonName)
	if err != nil {
		return nil, nil, fmt.Errorf("a.GenReq failed: %w", err)
	}

	if a.key == nil {
		a.key = key // self-sign
	}

	cert, err := a.SignReq(certType, req)
	if err != nil {
		return nil, nil, fmt.Errorf("a.SignReq failed: %w", err)
	}

	return cert, key, nil
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

func (a *Authority) SignReq(certType CertificateType, req *x509.CertificateRequest) (*x509.Certificate, error) {
	preCert, err := prepareCertificate(certType, req, a.cert)
	if err != nil {
		return nil, fmt.Errorf("prepareCertificate failed: %w", err)
	}

	if a.cert == nil {
		a.cert = preCert // self-sign
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, preCert, a.cert, req.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("x509.CreateCertificate failed: %w", err)
	}

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, fmt.Errorf("x509.ParseCertificate failed: %w", err)
	}

	return cert, nil
}
