package storage

type (
	KeyPair struct {
		SerialNumber string
		FriendlyName string
		Certificate  string
		PrivateKey   string

		Root    bool
		Revoked bool
	}

	Driver interface {
		Put(*KeyPair) error
		GetRoot() (*KeyPair, error)
		GetRevoked() ([]*KeyPair, error)
		GetBySerialNumber(string) (*KeyPair, error)
		GetByFriendlyName(string) ([]*KeyPair, error)
	}
)
