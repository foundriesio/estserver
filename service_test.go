package est

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/labstack/gommon/random"
	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
)

func createService(t *testing.T) Service {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			OrganizationalUnit: []string{random.String(10)},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	require.Nil(t, err)
	cert, err := x509.ParseCertificate(der)
	require.Nil(t, err)

	return Service{cert, cert, key}
}

func TestService_CA(t *testing.T) {
	log := InitLogger("")
	ctx := CtxWithLog(context.TODO(), log)

	s := createService(t)
	caBytes, err := s.CaCerts(ctx)
	require.Nil(t, err)

	caBytes, err = base64.StdEncoding.DecodeString(string(caBytes))
	require.Nil(t, err)
	p7, err := pkcs7.Parse(caBytes)
	require.Nil(t, err)
	cert := p7.Certificates[0]
	require.Equal(t, s.ca.RawSubject, cert.RawSubject)
}
