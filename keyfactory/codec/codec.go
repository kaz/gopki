package codec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
)

func EncodeToBytes(key crypto.Signer) ([]byte, error) {
	if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
		res, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return nil, fmt.Errorf("x509.MarshalECPrivateKey failed: %w", err)
		}
		return res, nil
	}
	if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		return x509.MarshalPKCS1PrivateKey(rsaKey), nil
	}
	return nil, fmt.Errorf("unexpected key type: %v", reflect.TypeOf(key))
}

func EncodeToPEM(key crypto.Signer) ([]byte, error) {
	keyType := ""
	switch key.(type) {
	case *ecdsa.PrivateKey:
		keyType = "EC PRIVATE KEY"
	case *rsa.PrivateKey:
		keyType = "RSA PRIVATE KEY"
	}

	bytes, err := EncodeToBytes(key)
	if err != nil {
		return nil, fmt.Errorf("EncodeToBytes failed: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: bytes}), nil
}
