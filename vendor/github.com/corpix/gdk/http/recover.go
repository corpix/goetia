package http

import (
	"fmt"

	"github.com/corpix/gdk/errors"
)

type (
	RecoverHandler func(ResponseWriter, *Request, error)
)

func MiddlewareRecover(errHandlerCtr func() RecoverHandler) Middleware {
	return func(h Handler) Handler {
		var errHandler RecoverHandler
		if errHandlerCtr != nil {
			errHandler = errHandlerCtr()
		}
		return HandlerFunc(func(w ResponseWriter, r *Request) {
			defer func() {
				if err := recover(); err != nil {
					w.WriteHeader(StatusInternalServerError)

					l := RequestLogGet(r)
					var e error
					switch typedErr := err.(type) {
					case error:
						e = typedErr
					default:
						e = errors.New(fmt.Sprint(err))
					}
					e = errors.WithStack(e)
					l.Error().Stack().Err(e).Msg("panic recover")
					if errHandler != nil {
						errHandler(w, r, e)
					}
				}
			}()
			h.ServeHTTP(w, r)
		})
	}
}
