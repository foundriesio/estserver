package est

import (
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
}
