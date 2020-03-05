package keyfactory

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type (
	Key struct {
		crypto.Signer
	}
)

func wrap(key interface{}) *Key {
	switch key.(type) {
	case *rsa.PrivateKey:
		return &Key{key.(*rsa.PrivateKey)}
	case *ecdsa.PrivateKey:
		return &Key{key.(*ecdsa.PrivateKey)}
	case ed25519.PrivateKey:
		return &Key{key.(ed25519.PrivateKey)}
	}
	return nil
}

func Parse(raw []byte) (*Key, error) {
	key, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKCS8PrivateKey failed: %w", err)
	}
	return wrap(key), nil
}

func ParsePEM(raw []byte) (*Key, error) {
	block, _ := pem.Decode(raw)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKCS8PrivateKey failed: %w", err)
	}
	return wrap(key), nil
}

func (k *Key) Bytes() ([]byte, error) {
	res, err := x509.MarshalPKCS8PrivateKey(k.Signer)
	if err != nil {
		return nil, fmt.Errorf("x509.MarshalPKCS8PrivateKey failed: %w", err)
	}
	return res, nil
}

func (k *Key) PEM(password []byte) ([]byte, error) {
	bytes, err := k.Bytes()
	if err != nil {
		return nil, fmt.Errorf("k.Bytes failed: %w", err)
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: bytes}
	if password != nil {
		encBlock, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", bytes, password, x509.PEMCipherAES256)
		if err != nil {
			return nil, fmt.Errorf("x509.EncryptPEMBlock failed: %w", err)
		}
		block = encBlock
	}

	return pem.EncodeToMemory(block), nil
}
