package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	est "github.com/foundriesio/estserver"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
)

type requiredStr struct {
	name  string
	value string
	help  string
}

func main() {
	required := []*requiredStr{
		{name: "tls-key", help: "Private key file of tls-cert"},
		{name: "tls-cert", help: "TLS PEM encoded certificate"},
		{name: "ca-key", help: "Private key file of EST CA"},
		{name: "ca-cert", help: "EST CA for handling enrollments"},
		{name: "root-cert", help: "EST CA PEM encoded root certificate"},
	}
	port := flag.Int("port", 8443, "Port to listen on")

	for _, opt := range required {
		flag.StringVar(&opt.value, opt.name, "", opt.help)
	}

	flag.Parse()

	log := est.InitLogger("")
	ctx := est.CtxWithLog(context.Background(), log)

	evt := log.Info().Int("port", *port)
	for _, opt := range required {
		if len(opt.value) == 0 {
			log.Fatal().Msgf("Missing required option: %s", opt.name)
		}
		evt = evt.Str(opt.name, opt.value)
	}
	evt.Msg("Starting")

	kp, err := tls.LoadX509KeyPair(required[1].value, required[0].value)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to loads TLS keypair")
	}

	rootCert := loadCert(log, required[4].value)
	caCert := loadCert(log, required[3].value)
	caKey := loadKey(log, required[2].value)

	caPool := x509.NewCertPool()
	caPool.AddCert(rootCert)
	caPool.AddCert(caCert)

	tlsCerts := est.TlsCerts{
		Server: &kp,
		Roots:  caPool,
	}
	tlsHandler, err := est.NewStaticTlsCertHandler(&tlsCerts)
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to create tls cert handler")
	}

	svc := est.NewService(rootCert, caCert, caKey)

	e := echo.New()
	s := http.Server{
		Addr:        fmt.Sprintf(":%d", *port),
		BaseContext: func(net.Listener) context.Context { return ctx },
		Handler:     e,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.VerifyClientCertIfGiven,
		},
	}
	if err = est.ApplyTlsCertHandler(s.TLSConfig, tlsHandler); err != nil {
		log.Fatal().Err(err).Msg("Unable to configure TLS handler")
	}
	est.RegisterEchoHandlers(svc, e)

	if err = est.RunGracefully(ctx, &s, e); err != nil {
		log.Fatal().Err(err).Msg("Unable to run server")
	}
}

func loadCert(log zerolog.Logger, fileName string) *x509.Certificate {
	bytes, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatal().Err(err).Msg("Can't read certificate")
	}
	block, extra := pem.Decode(bytes)
	if extra != nil && len(extra) > 0 {
		log.Fatal().Msgf("Can't parse CA key file. Extra bytes: %s", string(extra))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal().Err(err).Msg("Can't parse certificate")
	}
	return cert
}

func loadKey(log zerolog.Logger, keyFile string) *ecdsa.PrivateKey {
	bytes, err := os.ReadFile(keyFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Can't read CA key file")
	}
	block, extra := pem.Decode(bytes)
	if extra != nil && len(extra) > 0 {
		log.Fatal().Msgf("Can't parse CA key file. Extra bytes: %s", string(extra))
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal().Err(err).Msg("Can't parse CA key file")
	}
	return key
}
