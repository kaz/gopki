package agent

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/kaz/gopki/authority"
	"github.com/kaz/gopki/keyfactory"
	"github.com/kaz/gopki/storage"
)

type (
	Agent struct {
		driver  storage.Driver
		factory keyfactory.Factory
	}
)

func New(driver storage.Driver, factory keyfactory.Factory) *Agent {
	return &Agent{driver, factory}
}

func (a *Agent) ImportCA(rawCert []byte, rawKey []byte) error {
	certBlock, _ := pem.Decode(rawCert)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("x509.ParseCertificate failed: %w", err)
	}

	key, err := keyfactory.ParsePEM(rawKey)
	if err != nil {
		return fmt.Errorf("keyfactory.ParsePEM failed: %w", err)
	}

	return a.importCA(cert, key)
}

func (a *Agent) BuildCA(commonName string) error {
	caCert, caKey, err := authority.NewEmpty(a.factory).BuildFull(authority.CERT_TYPE_CA, commonName)
	if err != nil {
		return fmt.Errorf("authority.New.BuildCA failed: %w", err)
	}

	return a.importCA(caCert, caKey)
}

func (a *Agent) importCA(caCert *x509.Certificate, caKey crypto.Signer) error {
	rawKey, err := keyfactory.Wrap(caKey).Bytes()
	if err != nil {
		return fmt.Errorf("keyfactory.Wrap.Bytes failed: %w", err)
	}

	err = a.driver.Put(&storage.Entry{
		SerialNumber: hex.EncodeToString(caCert.SerialNumber.Bytes()),
		Subject:      caCert.Subject.String(),
		Certificate:  caCert.Raw,
		Key:          rawKey,
		Root:         true,
	})
	if err != nil {
		return fmt.Errorf("driver.Put failed: %w", err)
	}
	return nil
}

func (a *Agent) build(certType authority.CertificateType, commonName string) error {
	ent, err := a.driver.GetRoot()
	if err != nil {
		return fmt.Errorf("driver.GetRoot failed: %w", err)
	} else if ent == nil {
		return fmt.Errorf("no root CA: %w", err)
	}

	ca, err := authority.NewFromRaw(ent.Certificate, ent.Key, a.factory)
	if err != nil {
		return fmt.Errorf("authority.FromRaw failed: %w", err)
	}

	cert, key, err := ca.BuildFull(certType, commonName)
	if err != nil {
		return fmt.Errorf("ca.BuildClientFull failed: %w", err)
	}

	rawKey, err := keyfactory.Wrap(key).Bytes()
	if err != nil {
		return fmt.Errorf("keyfactory.Wrap.Bytes failed: %w", err)
	}

	err = a.driver.Put(&storage.Entry{
		SerialNumber: hex.EncodeToString(cert.SerialNumber.Bytes()),
		Subject:      cert.Subject.String(),
		Certificate:  cert.Raw,
		Key:          rawKey,
	})
	if err != nil {
		return fmt.Errorf("driver.Put failed: %w", err)
	}

	return nil
}

func (a *Agent) BuildClientFull(commonName string) error {
	return a.build(authority.CERT_TYPE_CLIENT, commonName)
}

func (a *Agent) BuildServerFull(commonName string) error {
	return a.build(authority.CERT_TYPE_SERVER, commonName)
}

func (a *Agent) ShowCA() ([]byte, error) {
	ent, err := a.driver.GetRoot()
	if err != nil {
		return nil, fmt.Errorf("driver.GetRoot failed: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ent.Certificate}), nil
}

func (a *Agent) ShowCert(commonName string) ([][]byte, error) {
	entries, err := a.driver.GetBySubject("CN=" + commonName)
	if err != nil {
		return nil, fmt.Errorf("driver.GetBySubject failed: %w", err)
	}

	certs := [][]byte{}
	for _, ent := range entries {
		certs = append(certs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ent.Certificate}))
	}
	return certs, nil
}
