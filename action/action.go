package action

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/kaz/gopki/authority"
	"github.com/kaz/gopki/keyfactory"
	"github.com/kaz/gopki/storage"
)

func launchCA(driver storage.Driver) (*authority.Authority, error) {
	ent, err := driver.GetRoot()
	if err != nil {
		return nil, fmt.Errorf("driver.GetRoot failed: %w", err)
	} else if ent == nil {
		return nil, fmt.Errorf("no root CA: %w", err)
	}

	ca, err := authority.FromRaw(ent.Certificate, ent.Key)
	if err != nil {
		return nil, fmt.Errorf("authority.FromRaw failed: %w", err)
	}

	return ca, nil
}

func BuildCA(commonName string, driver storage.Driver) error {
	caCert, caKey, err := authority.New(nil, nil).BuildCA(commonName)
	if err != nil {
		return fmt.Errorf("authority.New.BuildCA failed: %w", err)
	}

	rawKey, err := keyfactory.Wrap(caKey).Bytes()
	if err != nil {
		return fmt.Errorf("keyfactory.Wrap.Bytes failed: %w", err)
	}

	err = driver.Put(&storage.Entry{
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

func BuildClientFull(commonName string, driver storage.Driver) error {
	ca, err := launchCA(driver)
	if err != nil {
		return fmt.Errorf("launchCA failed: %w", err)
	}

	cert, key, err := ca.BuildClientFull(commonName)
	if err != nil {
		return fmt.Errorf("ca.BuildClientFull failed: %w", err)
	}

	rawKey, err := keyfactory.Wrap(key).Bytes()
	if err != nil {
		return fmt.Errorf("keyfactory.Wrap.Bytes failed: %w", err)
	}

	err = driver.Put(&storage.Entry{
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

func BuildServerFull(commonName string, driver storage.Driver) error {
	ca, err := launchCA(driver)
	if err != nil {
		return fmt.Errorf("launchCA failed: %w", err)
	}

	cert, key, err := ca.BuildServerFull(commonName)
	if err != nil {
		return fmt.Errorf("ca.BuildServerFull failed: %w", err)
	}

	rawKey, err := keyfactory.Wrap(key).Bytes()
	if err != nil {
		return fmt.Errorf("keyfactory.Wrap.Bytes failed: %w", err)
	}

	err = driver.Put(&storage.Entry{
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

func ShowCA(driver storage.Driver) ([]byte, error) {
	ent, err := driver.GetRoot()
	if err != nil {
		return nil, fmt.Errorf("driver.GetRoot failed: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ent.Certificate}), nil
}

func ShowCert(commonName string, driver storage.Driver) ([][]byte, error) {
	entries, err := driver.GetBySubject("CN=" + commonName)
	if err != nil {
		return nil, fmt.Errorf("driver.GetBySubject failed: %w", err)
	}

	certs := [][]byte{}
	for _, ent := range entries {
		certs = append(certs, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ent.Certificate}))
	}
	return certs, nil
}
