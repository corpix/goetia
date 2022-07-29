package proxy

import (
	"bytes"
	_ "embed"
	"io"

	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/template"
)

type (
	Template           = template.Template
	TemplateName       string
	TemplateContextKey = template.ContextKey
	TemplateContext    = template.Context
)

const (
	TemplateNameDocument  TemplateName = "document"
	TemplateNameSignin    TemplateName = "signin"
	TemplateNameSignout   TemplateName = "signout"
	TemplateNameAuthorize TemplateName = "authorize"
	TemplateNameStatus    TemplateName = "status"
	TemplateNameError     TemplateName = "error"

	TemplateContextKeyRequest     TemplateContextKey = http.TemplateContextKeyRequest
	TemplateContextKeyRequestId   TemplateContextKey = http.TemplateContextKeyRequestId
	TemplateContextKeySession     TemplateContextKey = http.TemplateContextKeySession
	TemplateContextKeyError       TemplateContextKey = "error"
	TemplateContextKeyUserProfile TemplateContextKey = "userProfile"
	TemplateContextKeyStyles      TemplateContextKey = "styles"
	TemplateContextKeyPaths       TemplateContextKey = "paths"
	TemplateContextKeyContainer   TemplateContextKey = "container"
	TemplateContextKeyConnectors  TemplateContextKey = "connectors"
)

var (
	//go:embed templates/main.css
	TemplateStyles string

	//go:embed templates/document.html
	TemplateDocument string

	//go:embed templates/signin.html
	TemplateSignin string

	//go:embed templates/signout.html
	TemplateSignout string

	//go:embed templates/authorize.html
	TemplateAuthorize string

	//go:embed templates/status.html
	TemplateStatus string

	//go:embed templates/error.html
	TemplateError string

	Templates = map[string]string{
		string(TemplateNameDocument):  TemplateDocument,
		string(TemplateNameSignin):    TemplateSignin,
		string(TemplateNameSignout):   TemplateSignout,
		string(TemplateNameAuthorize): TemplateAuthorize,
		string(TemplateNameStatus):    TemplateStatus,
		string(TemplateNameError):     TemplateError,
	}
)

func TemplateResponse(t *Template, ctx TemplateContext, w http.ResponseWriter) {
	w.Header().Add(http.HeaderContentType, http.MimeTextHtml)
	err := TemplateApply(t, ctx, w)
	if err != nil {
		panic(err)
	}
}

func TemplateApply(t *Template, ctx TemplateContext, w io.Writer) error {
	buf := bytes.NewBuffer(nil)
	err := t.Execute(buf, ctx)
	if err != nil {
		return err
	}
	err = t.Lookup(string(TemplateNameDocument)).Execute(w,
		ctx.
			With(TemplateContextKeyStyles, template.CSS(TemplateStyles)).
			With(TemplateContextKeyContainer, template.HTML(buf.String())),
	)
	if err != nil {
		return err
	}
	return nil
}
