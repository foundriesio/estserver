package est

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
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

	srv.TLS = &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven,
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
