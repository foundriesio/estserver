package est

import (
	"context"
	stdlog "log"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type (
	ctxKey int
)

const (
	loggerKey = ctxKey(100)
)

func InitLogger(level string) zerolog.Logger {
	// GCP log explorer uses the time/timestamp and severity fields from the JSON payload to filter log messages
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.LevelFieldName = "severity"
	log := zerolog.New(os.Stdout).With().Timestamp().Logger()
	if level == "" {
		level = os.Getenv("LOG_LEVEL")
		if level == "" {
			level = "info"
		}
	}
	l, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil {
		l = zerolog.InfoLevel
		log.Error().Msg("Cannot parse log level... continue as info")
	}
	log = log.Level(l)
	stdlog.SetFlags(0)
	genericLogger := log.With().
		Str("source", "stdlog").
		Str(zerolog.LevelFieldName, zerolog.LevelWarnValue).
		Logger()
	stdlog.SetOutput(genericLogger)
	return log
}

func CtxWithLog(ctx context.Context, log zerolog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, log)
}

func CtxGetLog(ctx context.Context) zerolog.Logger {
	return ctx.Value(loggerKey).(zerolog.Logger)
}
