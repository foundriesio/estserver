package est

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"

	"go.mozilla.org/pkcs7"
)

var (
	EstError = errors.New("Base EstError")
)

type EstErrorType int

const (
	ErrInvalidSignatureAlgorithm EstErrorType = iota
	ErrSubjectMismatch
	ErrSubjectAltNameMismatch
	ErrInvalidBase64
	ErrInvalidCsr
	ErrInvalidCsrSignature
)

func (e EstErrorType) Unwrap() error {
	return EstError
}
func (e EstErrorType) Error() string {
	switch e {
	case ErrInvalidSignatureAlgorithm:
		return "Signature algorithm of the CSR does not match that of the CA"
	case ErrSubjectMismatch:
		return "Subject field of CSR must match the current client certificate"
	case ErrSubjectAltNameMismatch:
		return "SubjectAltName field of CSR must match the current client certificate"
	case ErrInvalidBase64:
		return "The CSR payload is not base64 encoded"
	case ErrInvalidCsr:
		return "The CSR could not be decoded"
	case ErrInvalidCsrSignature:
		return "The CSR signature is invalid"
	}
	panic("Unsupported error type")
}

var (
	oidKeyUsage         = asn1.ObjectIdentifier([]int{2, 5, 29, 15})
	oidSubjectAltName   = asn1.ObjectIdentifier([]int{2, 5, 29, 17})
	oidExtendedKeyUsage = asn1.ObjectIdentifier([]int{2, 5, 29, 37})

	asn1DigitalSignature = []byte{3, 2, 7, 128}
	asn1TlsWebClientAuth = []byte{48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2}
)

// Service represents a thin API to handle required operations of EST7030
type Service struct {
	// Root CA for a Factory
	rootCa *x509.Certificate
	// ca and key are the EST7030 keypair used for signing EST7030 requests
	ca  *x509.Certificate
	key crypto.Signer
}

// NewService creates an EST7030 API for a Factory
func NewService(rootCa *x509.Certificate, ca *x509.Certificate, key crypto.Signer) Service {
	return Service{
		rootCa: rootCa,
		ca:     ca,
		key:    key,
	}
}

// CaCerts return the CA certificate as per:
// https://www.rfc-editor.org/rfc/rfc7030.html#section-4.1.2
func (s Service) CaCerts(ctx context.Context) ([]byte, error) {
	bytes, err := pkcs7.DegenerateCertificate(s.rootCa.Raw)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(bytes)), nil
}

// Enroll perform EST7030 enrollment operation as per
// https://www.rfc-editor.org/rfc/rfc7030.html#section-4.2.1
// Errors can be generic errors or of the type EstError
func (s Service) Enroll(ctx context.Context, csrBytes []byte) ([]byte, error) {
	panic("not implemented")
}

// ReEnroll perform EST7030 enrollment operation as per
// https://www.rfc-editor.org/rfc/rfc7030.html#section-4.2.2
// Errors can be generic errors or of the type EstError
func (s Service) ReEnroll(ctx context.Context, csrBytes []byte, curCert *x509.Certificate) ([]byte, error) {
	panic("not implemented")
}
