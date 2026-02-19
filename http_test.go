package est

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/random"
	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
)

const mimeTypePKCS7 = "application/pkcs7-mime"
const mimeTypePKCS7CertsOnly = "application/pkcs7-mime; smime-type=certs-only"

type testClient struct {
	svc Service
	srv *httptest.Server
	ctx context.Context
	old bool
}

type responseChecker func(t *testing.T, res *http.Response)

func checkHeaderValue(header string, expectedvalue string) responseChecker {
	var checker responseChecker = func(t *testing.T, res *http.Response) {
		require.Equal(t, expectedvalue, res.Header.Get(header), "Unexpected content-type")
	}
	return checker
}

func (tc testClient) GET(t *testing.T, resource string) []byte {
	url := tc.srv.URL + resource
	res, err := tc.srv.Client().Get(url)
	require.Nil(t, err)
	buf, err := io.ReadAll(res.Body)
	require.Nil(t, err)
	require.Equal(t, 200, res.StatusCode, string(buf))
	return buf
}

func (tc testClient) POST(t *testing.T, resource string, data []byte, cert *tls.Certificate, additionalChecks ...responseChecker) (int, []byte) {
	url := tc.srv.URL + resource
	client := tc.srv.Client()
	if cert != nil {
		transport := client.Transport.(*http.Transport)
		transport.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	require.Nil(t, err)
	req.Header.Set("Content-Type", "application/pkcs10")
	if tc.old {
		req.Header.Set("User-Agent", "fioconfig-client/2")
	}
	res, err := client.Do(req)

	require.Nil(t, err)
	buf, err := io.ReadAll(res.Body)
	require.Nil(t, err)
	for _, check := range additionalChecks {
		check(t, res)
	}
	return res.StatusCode, buf
}

func WithEstServer(t *testing.T, testFunc func(tc testClient)) {
	svc := createService(t)
	e := echo.New()
	RegisterEchoHandlers(NewStaticServiceHandler(svc), e)

	ctx := CtxWithLog(context.TODO(), InitLogger(""))
	srv := httptest.NewUnstartedServer(e)

	pool := x509.NewCertPool()
	for _, cert := range svc.rootCa {
		pool.AddCert(cert)
	}
	srv.TLS = &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	srv.Config.BaseContext = func(l net.Listener) context.Context { return ctx }

	tc := testClient{
		ctx: ctx,
		svc: svc,
		srv: srv,
	}

	testFunc(tc)
}

func TestCACertificatesRequest(t *testing.T) {
	WithEstServer(t, func(tc testClient) {
		buf := tc.GET(t, "/.well-known/est/cacerts")
		buf, err := base64.StdEncoding.DecodeString(string(buf))
		require.Nil(t, err)
		p7, err := pkcs7.Parse(buf)
		require.Nil(t, err)
		require.Equal(t, tc.svc.ca, p7.Certificates[0])
	})
}

func TestSimpleEnrollRequiresCert(t *testing.T) {
	WithEstServer(t, func(tc testClient) {
		rc, data := tc.POST(t, "/.well-known/est/simpleenroll", []byte{}, nil)
		require.Equal(t, 401, rc, string(data))
	})
}

func TestSimpleEnrollRequiresValidCert(t *testing.T) {
	WithEstServer(t, func(tc testClient) {
		svc := createService(t)

		kp := svc.createTlsKP(t, tc.ctx, "enrollRequiresValid")

		url := tc.srv.URL + "/.well-known/est/simpleenroll"
		client := tc.srv.Client()
		transport := client.Transport.(*http.Transport)
		transport.TLSClientConfig.Certificates = []tls.Certificate{*kp}

		res, err := client.Post(url, "application/pkcs10", bytes.NewBuffer([]byte{}))
		require.GreaterOrEqual(t, res.StatusCode, 400, "Server accepted invalid")
		require.Nil(t, err)
	})
}

func TestSimpleEnroll(t *testing.T) {
	WithEstServer(t, func(tc testClient) {
		cn := random.String(10)
		kp := tc.svc.createTlsKP(t, tc.ctx, cn)
		rc, data := tc.POST(t, "/.well-known/est/simpleenroll", []byte{}, kp)
		require.Equal(t, 400, rc, string(data))
		require.Equal(t, "The CSR could not be decoded: asn1: syntax error: sequence truncated", string(data))

		_, csr := createB64CsrDer(t, cn)
		rc, data = tc.POST(t, "/.well-known/est/simpleenroll", csr, kp, checkHeaderValue("content-type", mimeTypePKCS7CertsOnly))
		require.Equal(t, 200, rc, string(data))

		// backward compatablity test
		tc.old = true
		rc, data = tc.POST(t, "/.well-known/est/simpleenroll", csr, kp, checkHeaderValue("content-type", mimeTypePKCS7))
		require.Equal(t, 201, rc, string(data))
		tc.old = false

		buf, err := base64.StdEncoding.DecodeString(string(data))
		require.Nil(t, err)
		p7, err := pkcs7.Parse(buf)
		require.Nil(t, err)
		cert := p7.Certificates[0]
		require.Equal(t, cn, cert.Subject.CommonName)
	})
}

func TestSimpleReEnrollChecksSubject(t *testing.T) {
	WithEstServer(t, func(tc testClient) {
		cn := random.String(8)
		kp := tc.svc.createTlsKP(t, tc.ctx, cn)
		rc, data := tc.POST(t, "/.well-known/est/simplereenroll", []byte{}, kp)
		require.Equal(t, 400, rc, string(data))
		require.Equal(t, "The CSR could not be decoded: asn1: syntax error: sequence truncated", string(data))

		_, csr := createB64CsrDer(t, cn+"1")
		rc, data = tc.POST(t, "/.well-known/est/simplereenroll", csr, kp)
		require.Equal(t, 400, rc, string(data))
		require.Equal(t, ErrSubjectMismatch.Error(), string(data))
	})
}

func TestSimpleReEnroll(t *testing.T) {
	WithEstServer(t, func(tc testClient) {
		cn := random.String(9)
		kp := tc.svc.createTlsKP(t, tc.ctx, cn)
		rc, data := tc.POST(t, "/.well-known/est/simpleenroll", []byte{}, kp)
		require.Equal(t, 400, rc, string(data))
		require.Equal(t, "The CSR could not be decoded: asn1: syntax error: sequence truncated", string(data))

		newkey, csr := createB64CsrDer(t, cn)
		rc, data = tc.POST(t, "/.well-known/est/simplereenroll", csr, kp, checkHeaderValue("content-type", mimeTypePKCS7CertsOnly))
		require.Equal(t, 200, rc, string(data))

		// backward compatablity test
		tc.old = true
		rc, data = tc.POST(t, "/.well-known/est/simpleenroll", csr, kp, checkHeaderValue("content-type", mimeTypePKCS7))
		require.Equal(t, 201, rc, string(data))
		tc.old = false

		buf, err := base64.StdEncoding.DecodeString(string(data))
		require.Nil(t, err)
		p7, err := pkcs7.Parse(buf)
		require.Nil(t, err)
		cert := p7.Certificates[0]
		require.Equal(t, cn, cert.Subject.CommonName)

		// Now make sure this cert can authenticate to prove its valid
		kp = &tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  newkey,
		}

		rc, data = tc.POST(t, "/.well-known/est/simplereenroll", csr, kp, checkHeaderValue("content-type", mimeTypePKCS7CertsOnly))
		require.Equal(t, 200, rc, string(data))
	})
}

func TestServerKeygen(t *testing.T) {
	WithEstServer(t, func(tc testClient) {
		cn := random.String(10)
		kp := tc.svc.createTlsKP(t, tc.ctx, cn)
		rc, data := tc.POST(t, "/.well-known/est/serverkeygen", []byte{}, kp)
		require.Equal(t, 400, rc, string(data))
		require.Equal(t, "The CSR could not be decoded: asn1: syntax error: sequence truncated", string(data))

		var boundary string
		var extract responseChecker = func(t *testing.T, res *http.Response) {
			mediaType, params, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
			boundary = params["boundary"]
			require.Equal(t, "multipart/mixed", mediaType)
			require.Nil(t, err)
		} // ugly but boundary is in header but response is already read by POST()

		_, csr := createB64CsrDer(t, cn)
		rc, buf := tc.POST(t, "/.well-known/est/serverkeygen", csr, kp, extract)
		require.Equal(t, 200, rc, buf)

		// multipart structure
		mpr := multipart.NewReader(bytes.NewBuffer(buf), boundary)

		// certificate part
		part, err := mpr.NextPart()
		require.Nil(t, err, string(data))
		require.Equal(t, "application/pkcs7-mime; smime-type=certs-only", part.Header.Get("Content-Type"), "Wrong Content type for first part")
		bytebuf, err := io.ReadAll(part)
		require.Nil(t, err)
		cert, err := base64.StdEncoding.DecodeString(string(bytebuf))
		require.Nil(t, err)
		p7c, err := pkcs7.Parse(cert)
		require.Nil(t, err)
		require.Equal(t, 1, len(p7c.Certificates), "wrong amout of certs")

		// private key part
		part, err = mpr.NextPart()
		require.Nil(t, err, string(data))
		require.Equal(t, "application/pkcs8", part.Header.Get("Content-Type"), "Wrong Content type for first part")
		bytebuf, err = io.ReadAll(part)
		require.Nil(t, err)
		keyb, err := base64.StdEncoding.DecodeString(string(bytebuf))
		require.Nil(t, err)
		_, err = x509.ParsePKCS8PrivateKey(keyb)
		require.Nil(t, err)

		// test rejecting when service not allow serverkeygen
		rc, buf = tc.POST(t, "/.well-known/est/serverkeygen", csr, kp, extract)
		require.Equal(t, 200, rc, buf)
	})
}

func (s Service) createTlsKP(t *testing.T, ctx context.Context, cn string) *tls.Certificate {
	key, csrBytes := createB64CsrDer(t, cn)
	bytes, err := s.Enroll(ctx, csrBytes)
	require.Nil(t, err)

	bytes, err = base64.StdEncoding.DecodeString(string(bytes))
	require.Nil(t, err)
	p7, err := pkcs7.Parse(bytes)
	require.Nil(t, err)
	cert := p7.Certificates[0]
	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}
}
