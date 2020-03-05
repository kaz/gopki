package keyfactory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
)

type (
	EcdsaFactory struct {
		curve elliptic.Curve
	}
)

func NewEcdsaFactory(curve elliptic.Curve) Factory {
	return &EcdsaFactory{curve}
}

func (f *EcdsaFactory) NewKey() (*Key, error) {
	key, err := ecdsa.GenerateKey(f.curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey failed: %w", err)
	}
	return wrap(key), nil
}
