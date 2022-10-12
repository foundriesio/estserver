package est

import (
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/random"
)

const MAX_CONTENT_LEN = 4096

func accessLog(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		req := c.Request()
		res := c.Response()
		ctx := req.Context()
		log := CtxGetLog(ctx)

		rid := req.Header.Get(echo.HeaderXRequestID)
		if rid == "" {
			rid = random.String(12) // No need for uuid, save some space
		}
		res.Header().Set(echo.HeaderXRequestID, rid)
		log = log.With().Str("req_id", rid).Str("uri", req.RequestURI).Logger()
		if len(c.Request().TLS.PeerCertificates) == 1 {
			cert := c.Request().TLS.PeerCertificates[0]
			factory := ""
			if len(cert.Subject.OrganizationalUnit) > 0 {
				factory = cert.Subject.OrganizationalUnit[0]
			}
			log = log.With().
				Str("factory", factory).
				Str("device", cert.Subject.CommonName).
				Logger()
		}
		ctx = CtxWithLog(ctx, log)
		c.SetRequest(req.WithContext(ctx))

		contentLenStr := req.Header.Get(echo.HeaderContentLength)
		var contentLen uint64
		if len(contentLenStr) > 0 {
			var err error
			contentLen, err = strconv.ParseUint(contentLenStr, 10, 64)
			if err != nil {
				log.Error().
					Str("content-length", contentLenStr).
					Err(err).
					Msg("Non-numeric content-length")
			} else if contentLen > MAX_CONTENT_LEN {
				log.Error().
					Uint64("max-length", MAX_CONTENT_LEN).
					Uint64("content-length", contentLen).
					Msg("Content-length too large")
			}
		}

		if err := next(c); err != nil {
			c.Error(err)
		}
		duration := time.Since(start)

		// By now echo context might have been enriched by other middlewares
		req = c.Request()
		res = c.Response()
		ctx = req.Context()
		log = CtxGetLog(ctx)
		log.Info().
			Str("remote_ip", c.RealIP()).
			Str("host", req.Host).
			Str("method", req.Method).
			Str("user_agent", req.UserAgent()).
			Int("status", res.Status).
			Dur("duration_ms", duration).
			Uint64("bytes_in", contentLen).
			Int64("bytes_out", res.Size).
			Msg("Response stats")
		return nil
	}
}
