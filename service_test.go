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

	return Service{cert, cert, key, time.Hour * 24}
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
