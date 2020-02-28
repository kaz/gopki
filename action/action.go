package action

import (
	"encoding/hex"
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
		return fmt.Errorf("codec.EncodeToBytes failed: %w", err)
	}

	err = driver.Put(&storage.Entry{
		SerialNumber: hex.EncodeToString(caCert.SerialNumber.Bytes()),
		Subject:      caCert.Subject.String(),
		Certificate:  caCert.Raw,
		Key:          rawKey,
		Root:         true,
		Revoked:      false,
	})
	if err != nil {
		return fmt.Errorf("driver.Put failed: %w", err)
	}

	return nil
}
