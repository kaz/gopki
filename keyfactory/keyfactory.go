package keyfactory

import (
	"crypto/elliptic"
)

type (
	Factory interface {
		NewKey() (*Key, error)
	}
)

func Default() Factory {
	return NewEcdsaFactory(elliptic.P256())
}
