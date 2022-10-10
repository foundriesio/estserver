package est

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/labstack/echo/v4"
)

func RegisterEchoHandlers(svc Service, e *echo.Echo) {
	e.Use(accessLog)
	e.GET("/.well-known/est/cacerts", func(c echo.Context) error {
		certs, err := svc.CaCerts(c.Request().Context())
		if err != nil {
			return c.String(http.StatusInternalServerError, err.Error())
		}
		return c.Blob(200, "application/pkcs7-mime", certs)
	})
	e.POST("/.well-known/est/simpleenroll", func(c echo.Context) error {
		bytes, err := validateRequest(svc, c)
		if err != nil {
			return err
		}
		bytes, err = svc.Enroll(c.Request().Context(), bytes)
		if err != nil {
			if errors.Is(err, EstError) {
				return c.String(http.StatusBadRequest, err.Error())
			}
			return c.String(http.StatusInternalServerError, err.Error())
		}
		return c.Blob(http.StatusCreated, "application/pkcs7-mime", bytes)
	})
	e.POST("/.well-known/est/simplereenroll", func(c echo.Context) error {
		bytes, err := validateRequest(svc, c)
		if err != nil {
			return err
		}
		peerCerts := c.Request().TLS.PeerCertificates
		bytes, err = svc.ReEnroll(c.Request().Context(), bytes, peerCerts[0])
		if err != nil {
			if errors.Is(err, EstError) {
				return c.String(http.StatusBadRequest, err.Error())
			}
			return c.String(http.StatusInternalServerError, err.Error())
		}
		return c.Blob(http.StatusCreated, "application/pkcs7-mime", bytes)
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
