package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func createTestCert(t *testing.T, serialNumber int64) []byte {
	// Create a simple self-signed certificate for testing
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Generate a private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Encode the certificate as PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return certPEM
}

func createMultipleCertsFile(t *testing.T) string {
	// Create a temporary file with multiple certificates
	tmpFile, err := os.CreateTemp("", "test_certs*.pem")
	require.NoError(t, err)
	defer tmpFile.Close()

	// Create and write two certificates
	cert1 := createTestCert(t, 1001)
	cert2 := createTestCert(t, 1002)

	// Write both certificates to the file
	_, err = tmpFile.Write(cert1)
	require.NoError(t, err)
	_, err = tmpFile.Write(cert2)
	require.NoError(t, err)

	return tmpFile.Name()
}

func TestLoadCerts(t *testing.T) {
	// Create a test file with multiple certificates
	certFile := createMultipleCertsFile(t)
	defer os.Remove(certFile)

	// Create a logger
	log := zerolog.New(os.Stdout)

	// Test the loadCerts function
	certs := loadCerts(log, certFile)

	// Verify that we loaded two certificates
	require.Equal(t, 2, len(certs))

	// Verify that the certificates are valid
	require.NotNil(t, certs[0])
	require.NotNil(t, certs[1])

	// Verify that the certificates are different
	require.NotEqual(t, certs[0].SerialNumber, certs[1].SerialNumber)
}
