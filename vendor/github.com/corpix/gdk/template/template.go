package template

import (
	"encoding/base64"
	"html/template"
	"path"

	sprig "github.com/Masterminds/sprig/v3"
	qr "github.com/skip2/go-qrcode"

	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
	"github.com/davecgh/go-spew/spew"
)

type (
	CSS       = template.CSS
	Error     = template.Error
	ErrorCode = template.ErrorCode
	FuncMap   = template.FuncMap
	HTML      = template.HTML
	HTMLAttr  = template.HTMLAttr
	JS        = template.JS
	JSStr     = template.JSStr
	Srcset    = template.Srcset
	Template  = template.Template
	URL       = template.URL

	Option     func(*Template)
	Context    map[string]interface{}
	ContextKey string

	Config struct {
		Templates map[string]string `yaml:"templates"`
	}
)

var (
	HTMLEscape       = template.HTMLEscape
	HTMLEscapeString = template.HTMLEscapeString
	HTMLEscaper      = template.HTMLEscaper
	IsTrue           = template.IsTrue
	JSEscape         = template.JSEscape
	JSEscapeString   = template.JSEscapeString
	JSEscaper        = template.JSEscaper
	URLQueryEscaper  = template.URLQueryEscaper
	Must             = template.Must
	ParseFS          = template.ParseFS
	ParseFiles       = template.ParseFiles
	ParseGlob        = template.ParseGlob
)

func (c Context) With(key ContextKey, value interface{}) Context {
	c[string(key)] = value
	return c
}

func NewContext() Context { return Context{} }

//

func WithProvide(cont *di.Container) Option {
	return func(t *Template) {
		di.MustProvide(cont, func() *Template { return t })
	}
}

func WithInvoke(cont *di.Container, f di.Function) Option {
	return func(t *Template) { di.MustInvoke(cont, f) }
}

func WithConfig(c *Config) Option {
	return func(t *Template) {
		for name, data := range c.Templates {
			_, err := t.New(name).Parse(data)
			if err != nil {
				panic(errors.Wrap(err, "failed to parse"))
			}
		}
	}
}

func WithFuncMap(fm ...FuncMap) Option {
	return func(t *Template) {
		for _, f := range fm {
			t.Funcs(f)
		}
	}
}

func Parse(name string, data string) (*Template, error) {
	return New(name).Parse(data)
}

func DefaultFuncMap() FuncMap {
	m := sprig.FuncMap()
	em := FuncMap{
		"dump":     spew.Sdump,
		"pathJoin": path.Join,
		"qr": func(content string, size int) URL {
			q, err := qr.New(content, qr.Medium)
			if err != nil {
				panic(err)
			}
			buf, err := q.PNG(size)
			if err != nil {
				panic(err)
			}
			return URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(buf))
		},
	}
	for k, v := range em {
		m[k] = v
	}
	return m
}

func New(name string, options ...Option) *Template {
	t := template.New(name).Funcs(DefaultFuncMap())
	for _, option := range options {
		option(t)
	}
	return t
}
