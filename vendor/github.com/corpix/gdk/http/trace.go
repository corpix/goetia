package http

import (
	"context"

	"github.com/felixge/httpsnoop"
	"github.com/google/uuid"

	"github.com/corpix/gdk/log"
)

var (
	ContextKeyRequestId = new(ContextKey)
	ContextKeyLog       = new(ContextKey)
)

type TraceConfig struct {
	*SkipConfig `yaml:",inline,omitempty"`
}

func (c *TraceConfig) Default() {
	if c.SkipConfig == nil {
		c.SkipConfig = &SkipConfig{}
	}
}

//

func RequestIdGet(r *Request) string {
	ctxRequestId := r.Context().Value(ContextKeyRequestId)
	if ctxRequestId != nil {
		return ctxRequestId.(string)
	}

	return uuid.New().String()
}

func RequestIdSet(r *Request, id string) *Request {
	return r.WithContext(context.WithValue(r.Context(), ContextKeyRequestId, id))
}

//

func RequestLogGet(r *Request) log.Logger {
	ctxRequestLog := r.Context().Value(ContextKeyLog)
	if ctxRequestLog != nil {
		return ctxRequestLog.(log.Logger)
	}

	return log.With().
		Str("method", r.Method).
		Str("url", r.URL.String()).
		Logger()
}

func RequestLogSet(r *Request, l log.Logger) *Request {
	return r.WithContext(context.WithValue(r.Context(), ContextKeyLog, l))
}

//

func MiddlewareTrace(c *TraceConfig) Middleware {
	return func(next Handler) Handler {
		return HandlerFunc(func(w ResponseWriter, r *Request) {
			requestId := RequestIdGet(r)
			l := RequestLogGet(r).
				With().
				Str("request-id", requestId).
				Logger()

			r = RequestIdSet(r, requestId)
			r = RequestLogSet(r, l)

			if Skip(c.SkipConfig, r) {
				next.ServeHTTP(w, r)
				return
			}

			m := httpsnoop.CaptureMetrics(next, w, r)

			l.Info().
				Int("code", m.Code).
				Int64("written", m.Written).
				Dur("duration", m.Duration).
				Msg("request")
		})
	}
}
