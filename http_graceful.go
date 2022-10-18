package est

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
)

func RunGracefully(ctx context.Context, server *http.Server, e *echo.Echo) error {
	// setup channel to get notified on SIGTERM signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM)
	serveErr := make(chan error)

	// Start serving in goroutine and listen for stop signal in main thread
	go func() {
		if err := e.StartServer(server); err != http.ErrServerClosed {
			serveErr <- err
		}
	}()

	select {
	case err := <-serveErr:
		return err
	case <-quit:
		// shutdown the server with a grace period of configured timeout
		c, cancel := context.WithTimeout(ctx, 1*time.Minute)
		defer cancel()
		return server.Shutdown(c)
	}
}
