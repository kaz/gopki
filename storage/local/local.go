package local

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/kaz/gopki/storage"
)

type (
	Driver struct {
		path string
	}
)

func NewDriver(path string) storage.Driver {
	return &Driver{path}
}

func (d *Driver) get() ([]*storage.Entry, error) {
	data := []*storage.Entry{}

	f, err := os.Open(d.path)
	if errors.Is(err, os.ErrNotExist) {
		return data, nil
	} else if err != nil {
		return nil, fmt.Errorf("os.Open failed: %w", err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, fmt.Errorf("json.Decoder.Decode failed: %w", err)
	}

	return data, nil
}

func (d *Driver) Put(newEntry *storage.Entry) error {
	data, err := d.get()
	if err != nil {
		return fmt.Errorf("d.get failed: %w", err)
	}

	newData := []*storage.Entry{newEntry}
	for _, entry := range data {
		if entry.Root && newEntry.Root {
			continue
		}
		if entry.SerialNumber == newEntry.SerialNumber {
			continue
		}
		newData = append(newData, entry)
	}

	f, err := os.Create(d.path)
	if err != nil {
		return fmt.Errorf("os.Create failed: %w", err)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(newData); err != nil {
		return fmt.Errorf("json.Encoder.Encode failed: %w", err)
	}

	return nil
}

func (d *Driver) GetRoot() (*storage.Entry, error) {
	data, err := d.get()
	if err != nil {
		return nil, fmt.Errorf("d.get failed: %w", err)
	}

	for _, entry := range data {
		if entry.Root {
			return entry, nil
		}
	}

	return nil, nil
}

func (d *Driver) GetRevoked() ([]*storage.Entry, error) {
	data, err := d.get()
	if err != nil {
		return nil, fmt.Errorf("d.get failed: %w", err)
	}

	entries := []*storage.Entry{}
	for _, entry := range data {
		if entry.Revoked {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func (d *Driver) GetBySerialNumber(serialNumber string) (*storage.Entry, error) {
	data, err := d.get()
	if err != nil {
		return nil, fmt.Errorf("d.get failed: %w", err)
	}

	for _, entry := range data {
		if entry.SerialNumber == serialNumber {
			return entry, nil
		}
	}

	return nil, nil
}

func (d *Driver) GetBySubject(subject string) ([]*storage.Entry, error) {
	data, err := d.get()
	if err != nil {
		return nil, fmt.Errorf("d.get failed: %w", err)
	}

	entries := []*storage.Entry{}
	for _, entry := range data {
		if entry.Subject == subject {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}
