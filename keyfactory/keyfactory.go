package keyfactory

import (
	"crypto"
	"crypto/elliptic"
)

type (
	Factory interface {
		NewKey() (crypto.Signer, error)
	}
)

func Default() Factory {
	return NewEcdsaFactory(elliptic.P256())
}
