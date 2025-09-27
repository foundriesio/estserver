package est

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/labstack/gommon/random"
	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
)

func createB64CsrDer(t *testing.T, cn string) (crypto.Signer, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)

	template := x509.CertificateRequest{
		PublicKeyAlgorithm: 0,
		PublicKey:          key.PublicKey,
		Subject: pkix.Name{
			CommonName: cn,
		},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       oidKeyUsage,
				Critical: true,
				Value:    asn1DigitalSignature,
			},
			{
				Id:       oidExtendedKeyUsage,
				Critical: true,
				Value:    asn1TlsWebClientAuth,
			},
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	require.Nil(t, err)
	return key, []byte(base64.StdEncoding.EncodeToString(csrBytes))
}

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

	return Service{[]*x509.Certificate{cert}, cert, key, time.Hour * 24}
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
	require.Equal(t, s.rootCAs[0].RawSubject, cert.RawSubject)
}

func TestService_CaCertsWithMultipleRootCAs(t *testing.T) {
	term1 := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	term2 := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	validDays := 398
	// Create a test service with multiple root CA certificates
	log := InitLogger("")
	ctx := CtxWithLog(context.TODO(), log)

	// First root CA
	rootCAOld := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject: pkix.Name{
			OrganizationalUnit: []string{random.String(10)},
		},
		NotBefore:             term1,
		NotAfter:              term1.AddDate(0, 0, validDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Second root CA
	rootCANew := &x509.Certificate{
		SerialNumber: big.NewInt(201),
		Subject: pkix.Name{
			OrganizationalUnit: []string{random.String(10)},
		},
		NotBefore:             term2,
		NotAfter:              term2.AddDate(0, 0, validDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create keys for the certificates
	rootCAKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Old certificate
	require.Nil(t, err)
	der1, err := x509.CreateCertificate(rand.Reader, rootCAOld, rootCAOld, &rootCAKey.PublicKey, rootCAKey)
	require.Nil(t, err)
	rootCAOldCert, err := x509.ParseCertificate(der1)
	require.Nil(t, err)

	// New certificate
	der2, err := x509.CreateCertificate(rand.Reader, rootCANew, rootCANew, &rootCAKey.PublicKey, rootCAKey)
	require.Nil(t, err)
	rootCANewCert, err := x509.ParseCertificate(der2)
	require.Nil(t, err)

	// Create service with multiple root CAs
	// rootCAs is the list of the root CA certificates
	service := Service{[]*x509.Certificate{rootCAOldCert, rootCANewCert}, rootCAOldCert, rootCAKey, time.Hour * 24}
	caBytes, err := service.CaCerts(ctx)
	require.Nil(t, err)

	// Test that the response is properly base64 encoded
	caBytes, err = base64.StdEncoding.DecodeString(string(caBytes))
	require.Nil(t, err)

	// Test that the response is correctly parsed as PKCS7
	p7, err := pkcs7.Parse(caBytes)
	require.Nil(t, err)

	// Test that the response contains the correct root CA certificates
	// Test the response is correctly parsed
	require.Equal(t, 2, len(p7.Certificates))

	require.Equal(t, big.NewInt(101), p7.Certificates[0].SerialNumber)
	require.Equal(t, big.NewInt(201), p7.Certificates[1].SerialNumber)
}

func TestService_loadCsrBase64(t *testing.T) {
	log := InitLogger("")
	ctx := CtxWithLog(context.TODO(), log)

	// requires valid base64
	_, err := Service{}.loadCsr(ctx, []byte("not valid base64 data"))
	require.True(t, errors.Is(err, ErrInvalidBase64))

	// valid base64, invalid CSR
	content := base64.StdEncoding.EncodeToString([]byte("not a valid CSR"))
	_, err = Service{}.loadCsr(ctx, []byte(content))
	require.True(t, errors.Is(err, ErrInvalidCsr))
	require.True(t, errors.Is(err, ErrEst))

	// valid Csr
	cn := random.String(12)
	_, der := createB64CsrDer(t, cn)
	req, err := Service{}.loadCsr(ctx, der)
	require.Nil(t, err)
	require.Equal(t, cn, req.Subject.CommonName)
}

func TestService_signCsr(t *testing.T) {
	log := InitLogger("")
	ctx := CtxWithLog(context.TODO(), log)

	cn := random.String(12)
	s := createService(t)
	_, csrBytes := createB64CsrDer(t, cn)
	csr, err := s.loadCsr(ctx, csrBytes)
	require.Nil(t, err)

	bytes, err := s.signCsr(ctx, csr)
	require.Nil(t, err)
	bytes, err = base64.StdEncoding.DecodeString(string(bytes))
	require.Nil(t, err)
	p7, err := pkcs7.Parse(bytes)
	require.Nil(t, err)
	cert := p7.Certificates[0]
	require.Equal(t, cn, cert.Subject.CommonName)

	// X509 Key usage must be: DigitalSignature
	csr.Extensions[0].Value = []byte{3, 2, 7, 120}
	_, err = s.signCsr(ctx, csr)
	require.True(t, errors.Is(err, ErrInvalidCsr))

	// X509 ExtendedKey usage must be: TLS Web Client Authentication
	csr.Extensions[1].Value = csr.Extensions[0].Value
	csr.Extensions[0].Value = asn1DigitalSignature
	_, err = s.signCsr(ctx, csr)
	require.True(t, errors.Is(err, ErrInvalidCsr))
}

func TestService_Enroll(t *testing.T) {
	log := InitLogger("")
	ctx := CtxWithLog(context.TODO(), log)

	s := createService(t)
	cn := random.String(12)
	_, csrBytes := createB64CsrDer(t, cn)
	bytes, err := s.Enroll(ctx, csrBytes)
	require.Nil(t, err)

	bytes, err = base64.StdEncoding.DecodeString(string(bytes))
	require.Nil(t, err)
	p7, err := pkcs7.Parse(bytes)
	require.Nil(t, err)
	cert := p7.Certificates[0]
	require.Equal(t, cn, cert.Subject.CommonName)
}

func TestService_ReEnroll(t *testing.T) {
	log := InitLogger("")
	ctx := CtxWithLog(context.TODO(), log)

	cn := random.String(12)
	curCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: cn,
		},
	}

	s := createService(t)
	_, csrBytes := createB64CsrDer(t, cn)
	// curCert has not subject yet (it's not signed):
	_, err := s.ReEnroll(ctx, csrBytes, curCert)
	require.Equal(t, ErrSubjectMismatch, err)

	// Now create the cert:
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)
	der, err := x509.CreateCertificate(rand.Reader, curCert, curCert, &key.PublicKey, key)
	require.Nil(t, err)
	curCert, err = x509.ParseCertificate(der)
	require.Nil(t, err)

	bytes, err := s.ReEnroll(ctx, csrBytes, curCert)
	require.Nil(t, err)
	bytes, err = base64.StdEncoding.DecodeString(string(bytes))
	require.Nil(t, err)
	p7, err := pkcs7.Parse(bytes)
	require.Nil(t, err)
	cert := p7.Certificates[0]
	require.Equal(t, cn, cert.Subject.CommonName)
}
