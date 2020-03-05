package keyfactory

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
)

type (
	Key struct {
		crypto.Signer
	}
)

const (
	keyTypeEcdsa byte = iota
	keyTypeRsa

	blockTypeEcdsa = "EC PRIVATE KEY"
	blockTypeRsa   = "RSA PRIVATE KEY"
)

func Wrap(s crypto.Signer) *Key {
	return &Key{s}
}

func Parse(raw []byte) (crypto.Signer, error) {
	switch raw[0] {
	case keyTypeEcdsa:
		key, err := x509.ParseECPrivateKey(raw[1:])
		if err != nil {
			return nil, fmt.Errorf("x509.ParseECPrivateKey failed: %w", err)
		}
		return key, nil
	case keyTypeRsa:
		key, err := x509.ParsePKCS1PrivateKey(raw[1:])
		if err != nil {
			return nil, fmt.Errorf("x509.ParsePKCS1PrivateKey failed: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unexpected key type: %v", raw[0])
	}
}

func ParsePEM(raw []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(raw)

	switch block.Type {
	case blockTypeEcdsa:
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParseECPrivateKey failed: %w", err)
		}
		return key, nil
	case blockTypeRsa:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("x509.ParsePKCS1PrivateKey failed: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unexpected key type: %v", block.Type)
	}
}

func (k *Key) Bytes() ([]byte, error) {
	if ecdsaKey, ok := k.Signer.(*ecdsa.PrivateKey); ok {
		res, err := x509.MarshalECPrivateKey(ecdsaKey)
		if err != nil {
			return nil, fmt.Errorf("x509.MarshalECPrivateKey failed: %w", err)
		}
		return append([]byte{keyTypeEcdsa}, res...), nil
	}
	if rsaKey, ok := k.Signer.(*rsa.PrivateKey); ok {
		res := x509.MarshalPKCS1PrivateKey(rsaKey)
		return append([]byte{keyTypeRsa}, res...), nil
	}
	return nil, fmt.Errorf("unexpected key type: %v", reflect.TypeOf(k.Signer))
}

func (k *Key) PEM(password []byte) ([]byte, error) {
	blockType := ""
	switch k.Signer.(type) {
	case *ecdsa.PrivateKey:
		blockType = blockTypeEcdsa
	case *rsa.PrivateKey:
		blockType = blockTypeRsa
	default:
		return nil, fmt.Errorf("unexpected key type: %v", reflect.TypeOf(k.Signer))
	}

	bytes, err := k.Bytes()
	if err != nil {
		return nil, fmt.Errorf("k.Bytes failed: %w", err)
	}
	bytes = bytes[1:]

	block := &pem.Block{Type: blockType, Bytes: bytes}
	if password != nil {
		encBlock, err := x509.EncryptPEMBlock(rand.Reader, blockType, bytes, password, x509.PEMCipherAES256)
		if err != nil {
			return nil, fmt.Errorf("x509.EncryptPEMBlock failed: %w", err)
		}
		block = encBlock
	}

	return pem.EncodeToMemory(block), nil
}
