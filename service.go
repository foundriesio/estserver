package est

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

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

type ServiceHandler interface {
	GetService(ctx context.Context, serverName string) (Service, error)
}

type staticSvcHandler struct {
	Service
}

func (s staticSvcHandler) GetService(ctx context.Context, serverName string) (Service, error) {
	return s.Service, nil
}

func NewStaticServiceHandler(svc Service) ServiceHandler {
	return &staticSvcHandler{svc}
}

// Service represents a thin API to handle required operations of EST7030.
// This service implements the required parts of EST. Specifically:
//
//	"cas" - Section 4.1
//	"enroll" and "reenroll" - Section 4.2
//
// Optional APIs are not implemented including:
//
//	4.3 - cmc
//	4.4 - server side key generation
//	4.5 - CSR attributes
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
	csr, err := s.loadCsr(ctx, csrBytes)
	if err != nil {
		return nil, err
	}
	return s.signCsr(ctx, csr)
}

// ReEnroll perform EST7030 enrollment operation as per
// https://www.rfc-editor.org/rfc/rfc7030.html#section-4.2.2
// Errors can be generic errors or of the type EstError
func (s Service) ReEnroll(ctx context.Context, csrBytes []byte, curCert *x509.Certificate) ([]byte, error) {
	log := CtxGetLog(ctx)
	csr, err := s.loadCsr(ctx, csrBytes)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(csr.RawSubject, curCert.RawSubject) {
		log.Warn().
			Str("current-subject", curCert.Subject.String()).
			Str("requests-subject", csr.Subject.String()).
			Msg("Subject name mismatch")
		return nil, ErrSubjectMismatch
	}

	var csrSAN pkix.Extension
	var certSAN pkix.Extension
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			csrSAN = ext
			break
		}
	}
	for _, ext := range curCert.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			certSAN = ext
			break
		}
	}
	if !bytes.Equal(csrSAN.Value, certSAN.Value) {
		return nil, ErrSubjectAltNameMismatch
	}

	// TODO: Should we allow this:
	//   "The ChangeSubjectName attribute, as defined in [RFC6402], MAY be included
	//   in the CSR to request that these fields be changed in the new certificate."
	// Parts of the subject like dn,ou, and businessCategory=production *can't* be altered
	return s.signCsr(ctx, csr)
}

// loadCsr parses the certifcate signing request based on rules of
// https://www.rfc-editor.org/rfc/rfc7030.html#section-4.2.1
//   - content is a base64 encoded certificate signing request
func (s Service) loadCsr(ctx context.Context, bytes []byte) (*x509.CertificateRequest, error) {
	bytes, err := base64.StdEncoding.DecodeString(string(bytes))
	log := CtxGetLog(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Unable to decode base64 data")
		return nil, fmt.Errorf("%w: %s", ErrInvalidBase64, err)
	}
	csr, err := x509.ParseCertificateRequest(bytes)
	if err != nil {
		log.Error().Err(err).Msg("Unable to parse CSR")
		return nil, fmt.Errorf("%w: %s", ErrInvalidCsr, err)
	}
	if err = csr.CheckSignature(); err != nil {
		log.Error().Err(err).Msg("Invalid CSR Signature")
		return nil, fmt.Errorf("%w: %s", ErrInvalidCsrSignature, err)
	}
	return csr, nil
}

// signCsr returns a base64 PCKS7 encoded certificate as per
// https://www.rfc-editor.org/rfc/rfc7030.html#section-4.1.3
func (s Service) signCsr(ctx context.Context, csr *x509.CertificateRequest) ([]byte, error) {
	log := CtxGetLog(ctx)
	if s.ca.SignatureAlgorithm != csr.SignatureAlgorithm {
		return nil, ErrInvalidSignatureAlgorithm
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(1).Exp(big.NewInt(2), big.NewInt(128), nil))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	notAfter := now.Add(time.Hour * 24 * 365)
	if notAfter.After(s.ca.NotAfter) {
		log.Warn().Msg("Adjusting default cert expiry")
		notAfter = s.ca.NotAfter
	}

	// This deviates from 4.2.1, but we limit the extensions and not allow
	// clients to create CAs
	var ku x509.KeyUsage
	var eku []x509.ExtKeyUsage
	for _, e := range csr.Extensions {
		if e.Id.Equal(oidKeyUsage) {
			if !bytes.Equal(e.Value, asn1DigitalSignature) {
				log.Error().Bytes("Value", e.Value).Msg("Unsupported CSR KeyUsage options")
				return nil, fmt.Errorf("%w: Unsupported CSR KeyUsage value", ErrInvalidCsr)
			}
			ku |= x509.KeyUsageDigitalSignature
		} else if e.Id.Equal(oidExtendedKeyUsage) {
			if !bytes.Equal(e.Value, asn1TlsWebClientAuth) {
				log.Error().Bytes("Value", e.Value).Msg("Unsupported CSR ExtendedKeyUsage options")
				return nil, fmt.Errorf("%w: Unsupported CSR ExtendedKeyUsage value", ErrInvalidCsr)
			}
			eku = append(eku, x509.ExtKeyUsageClientAuth)
		} else {
			log.Error().Str("OID", e.Id.String()).Msg("Unsupported CSR Extension")
		}
	}

	var tmpl = &x509.Certificate{
		SerialNumber:          sn,
		NotBefore:             now,
		NotAfter:              notAfter,
		RawSubject:            csr.RawSubject,
		Signature:             csr.Signature,
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		Issuer:                s.ca.Subject,
		PublicKey:             csr.PublicKey,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca, csr.PublicKey, s.key)
	if err != nil {
		log.Error().Err(err).Msg("Unable to create new certificate")
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Error().Err(err).Msg("Unable to parse created certificate")
		return nil, err
	}
	bytes, err := pkcs7.DegenerateCertificate(cert.Raw)
	if err != nil {
		log.Error().Err(err).Msg("Unable to PKCS7 encode certificate")
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(bytes)), nil
}
