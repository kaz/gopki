package storage

type (
	Entry struct {
		SerialNumber string
		Subject      string

		Certificate []byte
		Key         []byte

		Root    bool
		Revoked bool
	}

	Driver interface {
		Put(*Entry) error
		GetRoot() (*Entry, error)
		GetRevoked() ([]*Entry, error)
		GetBySerialNumber(string) (*Entry, error)
		GetBySubject(string) ([]*Entry, error)
	}
)
