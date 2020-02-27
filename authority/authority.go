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

func New(cert *x509.Certificate, key crypto.Signer) *Authority {
	return &Authority{
		cert,
		key,
		keyfactory.Default(),
	}
}

func (a *Authority) BuildCA(caName string) (*x509.Certificate, crypto.Signer, error) {
	req, key, err := a.GenReq(caName)
	if err != nil {
		return nil, nil, fmt.Errorf("a.GenReq failed: %w", err)
	}

	a.key = key

	cert, err := a.SignReq(req, CERT_TYPE_CA)
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

func (a *Authority) SignReq(req *x509.CertificateRequest, certType CertificateType) (*x509.Certificate, error) {
	preCert, err := createPreCert(certType, req.Subject)
	if err != nil {
		return nil, fmt.Errorf("createPreCert failed: %w", err)
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
