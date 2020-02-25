package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/kaz/gopki/storage"
	"github.com/kaz/gopki/storage/local"
)

func main() {
	if err := _main(); err != nil {
		panic(err)
	}
}

func _main() error {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("rsa.GenerateKey failed: %w", err)
	}

	serialNumber := make([]byte, 16)
	if _, err := rand.Reader.Read(serialNumber); err != nil {
		return fmt.Errorf("rand.Reader.Read failed: %w", err)
	}

	t := time.Now()
	certTemp := &x509.Certificate{
		SerialNumber: big.NewInt(0).SetBytes(serialNumber),
		Subject: pkix.Name{
			CommonName: "gopki",
		},
		NotAfter:              t.Add((12*365 + 3) * 24 * time.Hour),
		NotBefore:             t,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCert, err := x509.CreateCertificate(rand.Reader, certTemp, certTemp, caKey.Public(), caKey)
	if err != nil {
		return fmt.Errorf("x509.CreateCertificate failed: %w", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert})
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})

	driver := local.NewDriver("store.json")
	err = driver.Put(&storage.KeyPair{
		SerialNumber: hex.EncodeToString(serialNumber),
		FriendlyName: "Root CA",
		Certificate:  string(caCertPEM),
		PrivateKey:   string(caKeyPEM),
		Root:         true,
		Revoked:      false,
	})
	if err != nil {
		return fmt.Errorf("driver.Put failed: %w", err)
	}

	return nil
}
