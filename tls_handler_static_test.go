package est

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStaticTlsCertHandler(t *testing.T) {
	svc := createService(t)

	der, err := x509.MarshalECPrivateKey(svc.key.(*ecdsa.PrivateKey))
	require.Nil(t, err)
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	keyPem := pem.EncodeToMemory(block)
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: svc.ca.Raw})

	cert, err := tls.X509KeyPair(certPem, keyPem)
	require.Nil(t, err)

	certs := &TlsCerts{
		Server: &cert,
		Roots:  &x509.CertPool{},
	}

	handler, err := NewStaticTlsCertHandler(certs)
	require.Nil(t, err)
	ctx := CtxWithLog(context.TODO(), InitLogger(""))
	require.Nil(t, handler.Init(ctx))

	certsFound, err := handler.Get(ctx, "example.com")
	require.Nil(t, err)
	require.Equal(t, certs, certsFound)

	called := false

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	t.Cleanup(server.Close)
	server.Config.BaseContext = func(net.Listener) context.Context { return ctx }
	server.TLS = &tls.Config{
		ClientAuth: tls.NoClientCert, // Bad option
		MinVersion: tls.VersionTLS12,
	}
	err = ApplyTlsCertHandler(server.TLS, handler)
	require.NotNil(t, err)

	server.TLS.ClientAuth = tls.VerifyClientCertIfGiven
	err = ApplyTlsCertHandler(server.TLS, handler)
	require.Nil(t, err)
	server.StartTLS()

	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	res, err := client.Get(server.URL)
	require.Nil(t, err)
	require.Equal(t, 200, res.StatusCode)
	require.True(t, called)
}
