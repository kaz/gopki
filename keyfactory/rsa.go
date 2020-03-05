package keyfactory

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

type (
	RsaFactory struct {
		bits int
	}
)

func NewRsaFactory(bits int) Factory {
	return &RsaFactory{bits}
}

func (f *RsaFactory) NewKey() (*Key, error) {
	key, err := rsa.GenerateKey(rand.Reader, f.bits)
	if err != nil {
		return nil, fmt.Errorf("rsa.GenerateKey failed: %w", err)
	}
	return wrap(key), nil
}
