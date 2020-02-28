package action

import (
	"encoding/hex"
	"fmt"

	"github.com/kaz/gopki/authority"
	"github.com/kaz/gopki/keyfactory/codec"
	"github.com/kaz/gopki/storage"
)

func BuildCA(commonName string, driver storage.Driver) error {
	caCert, caKey, err := authority.New(nil, nil).BuildCA(commonName)
	if err != nil {
		return fmt.Errorf("authority.New.BuildCA failed: %w", err)
	}

	rawKey, err := codec.EncodeToBytes(caKey)
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
