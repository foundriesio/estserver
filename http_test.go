package est

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/random"
	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
)

type testClient struct {
	svc Service
	srv *httptest.Server
	ctx context.Context
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

func (tc testClient) POST(t *testing.T, resource string, data []byte, cert *tls.Certificate) (int, []byte) {
	url := tc.srv.URL + resource
	client := tc.srv.Client()
	if cert != nil {
		transport := client.Transport.(*http.Transport)
		transport.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	}

	res, err := client.Post(url, "application/pkcs10", bytes.NewBuffer(data))
	require.Nil(t, err)
	buf, err := io.ReadAll(res.Body)
	require.Nil(t, err)
	return res.StatusCode, buf
}

func WithEstServer(t *testing.T, testFunc func(tc testClient)) {
	svc := createService(t)
	e := echo.New()
	RegisterEchoHandlers(svc, e)

	ctx := CtxWithLog(context.TODO(), InitLogger(""))
	srv := httptest.NewUnstartedServer(e)

	pool := x509.NewCertPool()
	pool.AddCert(svc.rootCa)
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

		url := tc.srv.URL + ".well-known/est/simpleenroll"
		client := tc.srv.Client()
		transport := client.Transport.(*http.Transport)
		transport.TLSClientConfig.Certificates = []tls.Certificate{*kp}

		_, err := client.Post(url, "application/pkcs10", bytes.NewBuffer([]byte{}))
		require.NotNil(t, err)
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
		rc, data = tc.POST(t, "/.well-known/est/simpleenroll", csr, kp)
		require.Equal(t, 201, rc, string(data))

		buf, err := base64.StdEncoding.DecodeString(string(data))
		require.Nil(t, err)
		p7, err := pkcs7.Parse(buf)
		require.Nil(t, err)
		cert := p7.Certificates[0]
		require.Equal(t, cn, cert.Subject.CommonName)
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
