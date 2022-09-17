package http

import (
	"bytes"
)

type (
	BufferedResponseConfig struct {
		*SkipConfig `yaml:",inline,omitempty"`
	}

	BufferedResponseWriter struct {
		ResponseWriter
		Code int
		Body *bytes.Buffer
	}
)

var (
	_ ResponseWriter = new(BufferedResponseWriter)
)

func (c *BufferedResponseConfig) Default() {
	if c.SkipConfig == nil {
		c.SkipConfig = &SkipConfig{}
	}
}

//

func (w *BufferedResponseWriter) WriteHeader(code int)          { w.Code = code }
func (w *BufferedResponseWriter) Write(buf []byte) (int, error) { return w.Body.Write(buf) }
func (w *BufferedResponseWriter) Flush() error {
	w.ResponseWriter.WriteHeader(w.Code)
	_, err := w.ResponseWriter.Write(w.Body.Bytes())
	return err
}

func NewBufferedResponseWriter(w ResponseWriter) *BufferedResponseWriter {
	return &BufferedResponseWriter{
		ResponseWriter: w,
		Code:           StatusOK,
		Body:           bytes.NewBuffer(nil),
	}
}

func MiddlewareBufferedResponse(c *BufferedResponseConfig) Middleware {
	return func(h Handler) Handler {
		return HandlerFunc(func(w ResponseWriter, r *Request) {
			if Skip(c.SkipConfig, r) {
				h.ServeHTTP(w, r)
				return
			}

			bw := NewBufferedResponseWriter(w)
			defer bw.Flush()
			h.ServeHTTP(bw, r)
		})
	}
}
