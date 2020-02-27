package authority

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

type (
	CertificateType string
)

const (
	CERT_TYPE_CA     CertificateType = "ca"
	CERT_TYPE_SERVER CertificateType = "server"
	CERT_TYPE_CLIENT CertificateType = "client"
)

func createPreCert(certType CertificateType, subject pkix.Name) (*x509.Certificate, error) {
	serialNumber := make([]byte, 16)
	if _, err := rand.Reader.Read(serialNumber); err != nil {
		return nil, fmt.Errorf("rand.Reader.Read failed: %w", err)
	}

	now := time.Now()
	preCert := &x509.Certificate{
		SerialNumber: big.NewInt(0).SetBytes(serialNumber),
		Subject:      subject,
		NotBefore:    now,
	}

	switch certType {
	case CERT_TYPE_CA:
		preCert.IsCA = true
		preCert.BasicConstraintsValid = true
		preCert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		preCert.NotAfter = now.Add((16*365 + 4) * 24 * time.Hour)
	case CERT_TYPE_SERVER:
		preCert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		preCert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		preCert.NotAfter = now.Add((8*365 + 2) * 24 * time.Hour)
	case CERT_TYPE_CLIENT:
		preCert.KeyUsage = x509.KeyUsageDigitalSignature
		preCert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		preCert.NotAfter = now.Add((4*365 + 1) * 24 * time.Hour)
	default:
		return nil, fmt.Errorf("invalid certificate type: %v", certType)
	}

	return preCert, nil
}
