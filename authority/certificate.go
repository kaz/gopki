package authority

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

func prepareCertificate(certType CertificateType, req *x509.CertificateRequest, parent *x509.Certificate) (*x509.Certificate, error) {
	serialNumber := make([]byte, 16)
	if _, err := rand.Reader.Read(serialNumber); err != nil {
		return nil, fmt.Errorf("rand.Reader.Read failed: %w", err)
	}

	var pkInfo struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	if _, err := asn1.Unmarshal(req.RawSubjectPublicKeyInfo, &pkInfo); err != nil {
		return nil, fmt.Errorf("asn1.Unmarshal failed: %w", err)
	}

	keyId := sha1.Sum(pkInfo.BitString.Bytes)

	now := time.Now()
	preCert := &x509.Certificate{
		SerialNumber:          big.NewInt(0).SetBytes(serialNumber),
		Subject:               req.Subject,
		NotBefore:             now,
		BasicConstraintsValid: true,
		SubjectKeyId:          keyId[:],
		AuthorityKeyId:        keyId[:],
	}

	if parent != nil {
		preCert.AuthorityKeyId = parent.AuthorityKeyId
	}

	switch certType {
	case CERT_TYPE_CA:
		preCert.IsCA = true
		preCert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		preCert.NotAfter = now.Add((16*365 + 4) * 24 * time.Hour)
	case CERT_TYPE_SERVER:
		preCert.IsCA = false
		preCert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		preCert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		preCert.NotAfter = now.Add((8*365 + 2) * 24 * time.Hour)
	case CERT_TYPE_CLIENT:
		preCert.IsCA = false
		preCert.KeyUsage = x509.KeyUsageDigitalSignature
		preCert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		preCert.NotAfter = now.Add((4*365 + 1) * 24 * time.Hour)
	default:
		return nil, fmt.Errorf("invalid certificate type: %v", certType)
	}

	return preCert, nil
}
