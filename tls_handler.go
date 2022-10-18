package est

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	errNoCerts = errors.New("Unable to find certs for this server")
)

// TlsCerts represents the Server TLS keypair to advertise and CA roots we trust
// for client authentication.
type TlsCerts struct {
	Server *tls.Certificate
	Roots  *x509.CertPool
}

// TLSCertHandler provides a way to hook into Go's HTTPS implementation to
// support different TLS Certs based on the incoming SNI server name.
type TlsCertHandler interface {
	Init(ctx context.Context) error
	Get(ctx context.Context, serverName string) (*TlsCerts, error)
	VerifyConnection(ctx context.Context, certs *TlsCerts, conn tls.ConnectionState) error
}

// Apply the TlsCertHandler logic to the tlsConfig
func ApplyTlsCertHandler(tlsConfig *tls.Config, handler TlsCertHandler) error {
	if tlsConfig.ClientAuth != tls.VerifyClientCertIfGiven {
		return fmt.Errorf("Invalid TLS ClientAuth value: %d. It must be `tls.VerifyClientCertIfGiven` to fulfill EST requirements", tlsConfig.ClientAuth)
	}
	tlsConfig.GetConfigForClient = func(helloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
		return getConfigForClient(tlsConfig, handler, helloInfo)
	}
	return nil
}

func getConfigForClient(tlsConfig *tls.Config, handler TlsCertHandler, helloInfo *tls.ClientHelloInfo) (*tls.Config, error) {
	ctx := helloInfo.Context()
	log := CtxGetLog(ctx)
	log.Debug().
		Stringer("from_addr", helloInfo.Conn.RemoteAddr()).
		Stringer("to_addr", helloInfo.Conn.LocalAddr()).
		Str("server", helloInfo.ServerName).
		Uints16("tls_ver", helloInfo.SupportedVersions).
		// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
		Uints16("ciphers", helloInfo.CipherSuites).
		Msg("New TLS connection")

	certs, err := handler.Get(ctx, helloInfo.ServerName)
	if err != nil {
		return nil, err
	}
	if certs == nil {
		return nil, errNoCerts
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{*certs.Server},
		ClientAuth:   tlsConfig.ClientAuth,
		ClientCAs:    certs.Roots,
		// We don't use the session resumption, save some CPU ticks on generating a secure ticket.
		SessionTicketsDisabled: true,
		VerifyConnection: func(con tls.ConnectionState) error {
			return handler.VerifyConnection(ctx, certs, con)
		},
	}
	return cfg, nil
}
