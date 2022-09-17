package http

import (
	"github.com/corpix/gdk/template"
)

const (
	TemplateContextKeyRequest   template.ContextKey = "request"
	TemplateContextKeyRequestId template.ContextKey = "requestId"
	TemplateContextKeySession   template.ContextKey = "session"
)

func NewTemplateContext(r *Request) template.Context {
	return template.NewContext().
		With(TemplateContextKeyRequest, r).
		With(TemplateContextKeyRequestId, RequestIdGet(r))
}
