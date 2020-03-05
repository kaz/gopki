package keyfactory

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

type (
	Ed25519Factory struct{}
)

func NewEd25519Factory() Factory {
	return &Ed25519Factory{}
}

func (f *Ed25519Factory) NewKey() (*Key, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519.GenerateKey failed: %w", err)
	}
	return wrap(key), nil
}
