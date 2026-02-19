package est

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"

	"github.com/labstack/echo/v4"
)

func RegisterEchoHandlers(svcHandler ServiceHandler, e *echo.Echo) {
	e.Use(accessLog)
	e.GET("/.well-known/est/cacerts", func(c echo.Context) error {
		svc, err := svcHandler.GetService(c.Request().Context(), c.Request().TLS.ServerName)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		certs, err := svc.CaCerts(c.Request().Context())
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		c.Response().Header().Set("Content-Transfer-Encoding", "base64")
		return c.Blob(200, "application/pkcs7-mime", certs)
	})
	e.POST("/.well-known/est/simpleenroll", func(c echo.Context) error {
		svc, err := svcHandler.GetService(c.Request().Context(), c.Request().TLS.ServerName)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		bytes, err := validateRequest(svc, c)
		if err != nil || bytes == nil { // validateRequest failed and sent the response
			return err
		}
		bytes, err = svc.Enroll(c.Request().Context(), bytes)
		if err != nil {
			if errors.Is(err, ErrEst) {
				return c.String(http.StatusBadRequest, err.Error())
			}
			return c.String(http.StatusInternalServerError, err.Error())
		}
		c.Response().Header().Set("Content-Transfer-Encoding", "base64")
		if c.Request().UserAgent() == "fioconfig-client/2" {
			// Older versions of fioconfig are requiring status code 201 and were not ignoring an optional `smime-type` extension.
			// Thus, we have to return whatever it expects for backward compatibility with devices already deployed.
			return c.Blob(http.StatusCreated, "application/pkcs7-mime", bytes)
		}
		return c.Blob(http.StatusOK, "application/pkcs7-mime; smime-type=certs-only", bytes)
	})
	e.POST("/.well-known/est/simplereenroll", func(c echo.Context) error {
		svc, err := svcHandler.GetService(c.Request().Context(), c.Request().TLS.ServerName)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		bytes, err := validateRequest(svc, c)
		if err != nil || bytes == nil { // validateRequest failed and sent the response
			return err
		}
		peerCerts := c.Request().TLS.PeerCertificates
		bytes, err = svc.ReEnroll(c.Request().Context(), bytes, peerCerts[0])
		if err != nil {
			if errors.Is(err, ErrEst) {
				return c.String(http.StatusBadRequest, err.Error())
			}
			return c.String(http.StatusInternalServerError, err.Error())
		}
		c.Response().Header().Set("Content-Transfer-Encoding", "base64")
		if c.Request().UserAgent() == "fioconfig-client/2" {
			// Older versions of fioconfig are requiring status code 201 and were not ignoring an optional `smime-type` extension.
			// Thus, we have to return whatever it expects for backward compatibility with devices already deployed.
			return c.Blob(http.StatusCreated, "application/pkcs7-mime", bytes)
		}
		return c.Blob(http.StatusOK, "application/pkcs7-mime; smime-type=certs-only", bytes)
	})

	e.POST("/.well-known/est/serverkeygen", func(c echo.Context) error {
		svc, err := svcHandler.GetService(c.Request().Context(), c.Request().TLS.ServerName)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		if !svc.allowServerKeygen {
			return c.String(http.StatusBadRequest, "this server does not allow server-side keygen")
		}
		reqbytes, err := validateRequest(svc, c)
		if err != nil || reqbytes == nil { // validateRequest failed and sent the response
			return err
		}
		peerCerts := c.Request().TLS.PeerCertificates
		crt, pkey, err := svc.ServerKeygen(c.Request().Context(), reqbytes, peerCerts[0])
		if err != nil {
			if errors.Is(err, ErrEst) {
				return c.String(http.StatusBadRequest, err.Error())
			}
			return c.String(http.StatusInternalServerError, err.Error())
		}
		mw := new(bytes.Buffer)
		mpWriter := multipart.NewWriter(mw)

		crtHeader := make(textproto.MIMEHeader)
		crtHeader.Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
		crtHeader.Set("Content-Transfer-Encoding", "base64")
		partC, _ := mpWriter.CreatePart(crtHeader)
		_, err = partC.Write(crt)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}

		keyHeader := make(textproto.MIMEHeader)
		keyHeader.Set("Content-Type", "application/pkcs8")
		keyHeader.Set("Content-Transfer-Encoding", "base64")
		partK, _ := mpWriter.CreatePart(keyHeader)
		_, err = partK.Write(pkey)
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		err = mpWriter.Close()
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		contentType := "multipart/mixed; boundary=" + mpWriter.Boundary()
		return c.Blob(http.StatusOK, contentType, mw.Bytes())
	})
}

// validateRequest checks that the client has provided a client cert (via mTLS)
// as per: https://www.rfc-editor.org/rfc/rfc7030.html#section-3.3.2
// and has set the correct request content-type as per:
// https://www.rfc-editor.org/rfc/rfc7030.html#section-4.2.1
func validateRequest(svc Service, c echo.Context) ([]byte, error) {
	if len(c.Request().TLS.PeerCertificates) != 1 {
		return nil, c.String(http.StatusUnauthorized, "Client must provide certificate")
	}
	ct := c.Request().Header.Get("content-type")
	if ct != "application/pkcs10" {
		return nil, c.String(http.StatusBadRequest, fmt.Sprintf("Invalid content-type: %s. Must be application/pkcs10", ct))
	}
	return io.ReadAll(c.Request().Body)
}
