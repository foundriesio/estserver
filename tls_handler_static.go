package est

import (
	"context"
	"crypto/tls"
)

type staticHandler struct {
	certs *TlsCerts
}

// Createa a TlsCertHandler based on a static keyfile and certificate
func NewStaticTlsCertHandler(certs *TlsCerts) (TlsCertHandler, error) {
	return &staticHandler{certs}, nil
}

func (h staticHandler) Init(ctx context.Context) error {
	return nil
}
func (h staticHandler) Get(ctx context.Context, serverName string) (*TlsCerts, error) {
	return h.certs, nil
}

func (h staticHandler) VerifyConnection(certs *TlsCerts, conn tls.ConnectionState) error {
	return nil
}
