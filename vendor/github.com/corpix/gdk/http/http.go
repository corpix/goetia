package http

import (
	"net/http"
	"net/url"

	"path/filepath"

	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/log"
	"github.com/corpix/gdk/template"
)

type (
	Config struct {
		Url              *UrlConfig              `yaml:"url"`
		Address          string                  `yaml:"address"`
		Prefix           string                  `yaml:"prefix"`
		BufferedResponse *BufferedResponseConfig `yaml:"buffered-response"`
		Metrics          *MetricsConfig          `yaml:"metrics"`
		Trace            *TraceConfig            `yaml:"trace"`
		Session          *SessionConfig          `yaml:"session"`
		Csrf             *CsrfConfig             `yaml:"csrf"`
		Proxy            *ProxyConfig            `yaml:"proxy"`
		Template         *template.Config        `yaml:"template"`
	}
	Http struct {
		Config  *Config
		Address string
		Router  *Router
	}
	Option         func(*Http)
	Handler        = http.Handler
	HandlerFunc    = http.HandlerFunc
	Middleware     = func(Handler) Handler
	Request        = http.Request
	ResponseWriter = http.ResponseWriter
	Response       = http.Response
	Header         = http.Header
	ContextKey     uint8

	UrlConfig struct {
		Scheme   string `yaml:"scheme"`
		Hostname string `yaml:"hostname"`
	}
	Url       = url.URL
	UrlOption func(*Url)
)

const (
	MethodGet     = http.MethodGet
	MethodHead    = http.MethodHead
	MethodPost    = http.MethodPost
	MethodPut     = http.MethodPut
	MethodPatch   = http.MethodPatch
	MethodDelete  = http.MethodDelete
	MethodConnect = http.MethodConnect
	MethodOptions = http.MethodOptions
	MethodTrace   = http.MethodTrace

	SchemeHttp  = "http"
	SchemeHttps = "https"

	HeaderAccept                          = "Accept"
	HeaderAcceptEncoding                  = "Accept-Encoding"
	HeaderAllow                           = "Allow"
	HeaderAuthorization                   = "Authorization"
	HeaderContentDisposition              = "Content-Disposition"
	HeaderContentEncoding                 = "Content-Encoding"
	HeaderContentLength                   = "Content-Length"
	HeaderContentType                     = "Content-Type"
	HeaderCookie                          = "Cookie"
	HeaderSetCookie                       = "Set-Cookie"
	HeaderIfModifiedSince                 = "If-Modified-Since"
	HeaderLastModified                    = "Last-Modified"
	HeaderLocation                        = "Location"
	HeaderRetryAfter                      = "Retry-After"
	HeaderUpgrade                         = "Upgrade"
	HeaderVary                            = "Vary"
	HeaderWwwAuthenticate                 = "WWW-Authenticate"
	HeaderForwardedFor                    = "X-Forwarded-For"
	HeaderForwardedProto                  = "X-Forwarded-Proto"
	HeaderForwardedProtocol               = "X-Forwarded-Protocol"
	HeaderForwardedSsl                    = "X-Forwarded-Ssl"
	HeaderUrlScheme                       = "X-Url-Scheme"
	HeaderHttpMethodOverride              = "X-HTTP-Method-Override"
	HeaderRealIp                          = "X-Real-Ip"
	HeaderRequestId                       = "X-Request-Id"
	HeaderCorrelationId                   = "X-Correlation-Id"
	HeaderRequestedWith                   = "X-Requested-With"
	HeaderServer                          = "Server"
	HeaderOrigin                          = "Origin"
	HeaderCacheControl                    = "Cache-Control"
	HeaderConnection                      = "Connection"
	HeaderAccessControlRequestMethod      = "Access-Control-Request-Method"
	HeaderAccessControlRequestHeaders     = "Access-Control-Request-Headers"
	HeaderAccessControlAllowOrigin        = "Access-Control-Allow-Origin"
	HeaderAccessControlAllowMethods       = "Access-Control-Allow-Methods"
	HeaderAccessControlAllowHeaders       = "Access-Control-Allow-Headers"
	HeaderAccessControlAllowCredentials   = "Access-Control-Allow-Credentials"
	HeaderAccessControlExposeHeaders      = "Access-Control-Expose-Headers"
	HeaderAccessControlMaxAge             = "Access-Control-Max-Age"
	HeaderStrictTransportSecurity         = "Strict-Transport-Security"
	HeaderContentTypeOptions              = "X-Content-Type-Options"
	HeaderXssProtection                   = "X-XSS-Protection"
	HeaderFrameOptions                    = "X-Frame-Options"
	HeaderContentSecurityPolicy           = "Content-Security-Policy"
	HeaderContentSecurityPolicyReportOnly = "Content-Security-Policy-Report-Only"
	HeaderCsrfToken                       = "X-CSRF-Token"
	HeaderReferrerPolicy                  = "Referrer-Policy"

	AuthTypeBearer = "bearer"
	AuthTypeBasic  = "basic"
)

var (
	Redirect = http.Redirect
)

func (c *Config) Default() {
	if c.Url == nil {
		c.Url = &UrlConfig{}
	}
	if c.BufferedResponse == nil {
		c.BufferedResponse = &BufferedResponseConfig{}
	}
	if c.Metrics == nil {
		c.Metrics = &MetricsConfig{}
	}
	if c.Trace == nil {
		c.Trace = &TraceConfig{}
	}
	if c.Session == nil {
		c.Session = &SessionConfig{TokenConfig: &TokenConfig{}}
	}
	if c.Csrf == nil {
		c.Csrf = &CsrfConfig{TokenConfig: &TokenConfig{}}
	}
	if c.Template == nil {
		c.Template = &template.Config{}
	}

	//

	if c.Metrics.Enable {
		c.Metrics.Default()
		metricsPath := filepath.Join(c.Prefix, c.Metrics.Path)

		c.BufferedResponse.Default()
		c.BufferedResponse.SkipConfig.Default()
		c.BufferedResponse.SkipPaths[metricsPath] = struct{}{}

		c.Trace.Default()
		c.Trace.SkipConfig.Default()
		c.Trace.SkipPaths[metricsPath] = struct{}{}

		c.Session.Default()
		if c.Session.Enable {
			c.Session.SkipConfig.Default()
			c.Session.SkipPaths[metricsPath] = struct{}{}
		}

		c.Csrf.Default()
		if c.Csrf.Enable {
			c.Csrf.SkipConfig.Default()
			c.Csrf.SkipPaths[metricsPath] = struct{}{}
		}
	}
}

func (c *Config) Validate() error {
	if c.Address == "" {
		return errors.New("address should not be empty")
	}
	return nil
}

func (c *UrlConfig) Default() {
	if c.Scheme == "" {
		c.Scheme = SchemeHttp
	}
}

//

func WithAddress(addr string) Option {
	return func(h *Http) { h.Address = addr }
}

func WithRouter(r *Router) Option {
	return func(h *Http) { h.Router = r }
}

func WithLogAvailableRoutes() Option {
	return func(h *Http) {
		_ = h.Router.Walk(func(route *Route, router *Router, ancestors []*Route) error {
			methods, _ := route.GetMethods()
			if len(methods) == 0 {
				// just skip routes without methods
				// routes like this could appear when PathPrefix used
				return nil
			}
			query, _ := route.GetQueriesTemplates()
			path, _ := route.GetPathTemplate()

			log.Info().
				Str("path", path).
				Strs("query", query).
				Strs("methods", methods).
				Msg("route")

			return nil
		})
	}
}

func WithProvide(cont *di.Container) Option {
	return func(h *Http) {
		di.MustProvide(cont, func() *Http { return h })
	}
}

func WithInvoke(cont *di.Container, f di.Function) Option {
	return func(h *Http) { di.MustInvoke(cont, f) }
}

func WithMiddleware(middlewares ...Middleware) Option {
	return func(h *Http) {
		for _, middleware := range middlewares {
			h.Router.Use(middleware)
		}
	}
}

func (h *Http) Url(u *url.URL, options ...UrlOption) *url.URL {
	uu := *u
	uu.Scheme = h.Config.Url.Scheme
	if h.Config.Url.Hostname != "" {
		uu.Host = h.Config.Url.Hostname
	}
	for _, option := range options {
		option(&uu)
	}
	return &uu
}

func (h *Http) ListenAndServe() error {
	if h.Address == "" {
		return errors.New("no address was defined for http server to listen on (use WithAddress Option)")
	}
	if h.Router == nil {
		return errors.New("no router assigned to the server (use WithRouter Option)")
	}
	log.Info().Str("address", h.Address).Msg("starting http server")
	return http.ListenAndServe(h.Address, h.Router)
}

func New(c *Config, options ...Option) *Http {
	h := &Http{
		Config:  c,
		Address: c.Address,
	}
	for _, option := range options {
		option(h)
	}

	return h
}
