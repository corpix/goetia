package proxy

import (
	"strings"

	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/reflect"
	"github.com/corpix/gdk/template"
)

type (
	Config struct {
		Prefix     string            `yaml:"prefix"`
		User       *UserConfig       `yaml:"user,omitempty"`
		Providers  *ProvidersConfig  `yaml:"providers,omitempty"`
		Connectors *ConnectorsConfig `yaml:"connectors,omitempty"`
	}

	PathName string
	Paths    map[PathName]string

	ConnectorsConfig struct {
		Enable   []string                 `yaml:"enable"`
		Basic    *ConnectorBasicConfig    `yaml:"basic"`
		Oauth    *ConnectorOauthConfig    `yaml:"oauth"`
		Telegram *ConnectorTelegramConfig `yaml:"telegram"`
	}
	ConnectorConfig struct {
		Name        string `yaml:"name"`
		Label       string `yaml:"label"`
		Description string `yaml:"description"`
	}
	ConnectorName string
	Connector     interface {
		Name() string
		Label() string
		Description() string
		Mount(*http.Router)
	}

	ProvidersConfig struct {
		Enable []string             `yaml:"enable"`
		Oauth  *ProviderOauthConfig `yaml:"oauth"`
		Oidc   *ProviderOidcConfig  `yaml:"oidc"`
	}
	ProviderName string
	Provider     interface {
		Name() string
		Label() string
		Description() string
		Mount(*http.Router)
	}

	KeyValue interface {
		Get(key string) string
		Set(key string, value string)
	}
)

const (
	PathNameRoot       PathName = "root"
	PathNameConnectors PathName = "connectors"
	PathNameSignin     PathName = "signin"
	PathNameSignout    PathName = "signout"
	PathNameProviders  PathName = "providers"
	PathNameAuthorize  PathName = "authorize"
	PathNameStatus     PathName = "status"

	PathRoot       = "/"
	PathConnectors = "/connectors"
	PathSignin     = "/signin"
	PathSignout    = "/signout"
	PathProviders  = "/providers"
	PathAuthorize  = "/authorize"
	PathStatus     = "/status"

	ConnectorNameBasic    ConnectorName = "basic"
	ConnectorNameOauth    ConnectorName = "oauth"
	ConnectorNameTelegram ConnectorName = "telegram"

	ProviderNameOauth ProviderName = "oauth"
	ProviderNameOidc  ProviderName = "oidc"
)

var (
	ConnectorNames = map[string]struct{}{
		string(ConnectorNameBasic):    {},
		string(ConnectorNameOauth):    {},
		string(ConnectorNameTelegram): {},
	}

	_ Connector = &ConnectorBasic{}
	_ Connector = &ConnectorOauth{}
	_ Connector = &ConnectorTelegram{}

	ProviderNames = map[string]struct{}{
		string(ProviderNameOauth): {},
		string(ProviderNameOidc):  {},
	}

	_ Provider = &ProviderOauth{}
	_ Provider = &ProviderOidc{}

	ErrAuthorizationRequired = errors.New("authorization required")
)

func MustProvide() {
	di.MustProvide(di.Default, func() []http.ProxyOption {
		var paths Paths
		return []http.ProxyOption{
			http.WithProxyPredicate(func(h *http.Http, w http.ResponseWriter, r *http.Request) bool {
				if paths == nil {
					di.MustInvoke(di.Default, func(p Paths) { paths = p })
				}

				session := http.RequestSessionMustGet(r)
				profile := SessionUserProfileGet(session)
				if profile == nil {
					http.Redirect(
						w, r,
						paths[PathNameSignin],
						http.StatusTemporaryRedirect,
					)
					return false
				}
				return true
			}),
		}
	})
}

//

func (p Paths) TemplateContext() TemplateContext {
	ctx := make(TemplateContext, len(p))
	for k, v := range p {
		ctx[string(k)] = v
	}
	return ctx
}

func NewPaths(prefix string) Paths {
	if prefix == "/" {
		prefix = ""
	}
	return Paths{
		PathNameRoot:       prefix + PathRoot,
		PathNameConnectors: prefix + PathConnectors,
		PathNameSignin:     prefix + PathSignin,
		PathNameSignout:    prefix + PathSignout,
		PathNameProviders:  prefix + PathProviders,
		PathNameAuthorize:  prefix + PathAuthorize,
		PathNameStatus:     prefix + PathStatus,
	}
}

//

func (c *ConnectorsConfig) Default() {
	enabled := map[ConnectorName]bool{}
	for _, k := range c.Enable {
		enabled[ConnectorName(strings.ToLower(k))] = true
	}

	if c.Basic == nil && enabled[ConnectorNameBasic] {
		c.Basic = &ConnectorBasicConfig{}
	}
	if c.Oauth == nil && enabled[ConnectorNameOauth] {
		c.Oauth = &ConnectorOauthConfig{}
	}
	if c.Telegram == nil && enabled[ConnectorNameTelegram] {
		c.Telegram = &ConnectorTelegramConfig{}
	}
}

func (c *ConnectorsConfig) Validate() error {
	if len(c.Enable) == 0 {
		return errors.New("connectors enable list is empty, you should enable one or more connectors")
	}
	for _, name := range c.Enable {
		_, exists := ConnectorNames[strings.ToLower(name)]
		if !exists {
			return errors.Errorf(
				"unsupported connector %q, available: %v",
				name, reflect.MapSortedKeys(reflect.ValueOf(ConnectorNames)),
			)
		}
	}
	return nil
}

func (c *ProvidersConfig) Default() {
	enabled := map[ProviderName]bool{}
	for _, k := range c.Enable {
		enabled[ProviderName(strings.ToLower(k))] = true
	}

	if c.Oauth == nil && enabled[ProviderNameOauth] {
		c.Oauth = &ProviderOauthConfig{}
	}
	if c.Oidc == nil && enabled[ProviderNameOidc] {
		c.Oidc = &ProviderOidcConfig{}
	}
}

func (c *ProvidersConfig) Validate() error {
	if len(c.Enable) == 0 {
		return errors.New("providers enable list is empty, you should enable one or more providers")
	}
	for _, name := range c.Enable {
		_, exists := ProviderNames[strings.ToLower(name)]
		if !exists {
			return errors.Errorf(
				"unsupported provider %q, available: %v",
				name, reflect.MapSortedKeys(reflect.ValueOf(ProviderNames)),
			)
		}
	}
	return nil
}

func NewConnectors(c *ConnectorsConfig) []Connector {
	if c == nil {
		return nil
	}

	connectors := make([]Connector, len(c.Enable))
	for n, name := range c.Enable {
		switch ConnectorName(name) {
		case ConnectorNameBasic:
			connectors[n] = NewConnectorBasic(c.Basic)
		case ConnectorNameOauth:
			connectors[n] = NewConnectorOauth(c.Oauth)
		case ConnectorNameTelegram:
			connectors[n] = NewConnectorTelegram(c.Telegram)
		}
	}
	return connectors
}

func NewProviders(c *ProvidersConfig) []Provider {
	if c == nil {
		return nil
	}

	providers := make([]Provider, len(c.Enable))
	for n, name := range c.Enable {
		_ = n
		switch ProviderName(name) {
		case ProviderNameOauth:
			providers[n] = NewProviderOauth(c.Oauth)
		case ProviderNameOidc:
			providers[n] = NewProviderOidc(c.Oidc)
		}
	}
	return providers
}

func ErrorHandlerCtr(t *template.Template, ps Paths) http.RecoverHandler {
	errTemplate := t.Lookup(string(TemplateNameError))
	paths := ps.TemplateContext()
	return func(w http.ResponseWriter, r *http.Request, err error) {
		TemplateResponse(
			errTemplate,
			http.
				NewTemplateContext(r).
				With(TemplateContextKeyPaths, paths).
				With(TemplateContextKeyError, err.Error()),
			w,
		)
	}
}

func Serve(conf *Config, h *http.Http, t *template.Template) {
	r := h.Router
	if conf.Prefix != "" {
		r = r.PathPrefix(conf.Prefix).Subrouter()
	}

	if conf.User.Profile.Headers.Enable {
		headersService := NewUserProfileHeadersService(conf.User.Profile.Headers)
		di.MustProvide(di.Default, func() *UserProfileHeadersService { return headersService })
		h.Router.Use(MiddlewareUserProfileHeaders(headersService))
	}

	//

	paths := NewPaths(conf.Prefix)
	templatePaths := paths.TemplateContext()
	retpathRules := NewUserProfileRetpathRules(conf.User.Retpath.Rules)
	userProfileRules := NewUserProfileRules(conf.User.Profile.Rules)

	//

	di.MustProvide(di.Default, func() UserProfileRetpathRules { return retpathRules })
	di.MustProvide(di.Default, func() UserProfileRules { return userProfileRules })
	di.MustProvide(di.Default, func() Paths { return paths })

	//

	connectors := NewConnectors(conf.Connectors)
	for _, connector := range connectors {
		connector.Mount(r.PathPrefix(PathConnectors + "/" + connector.Name()).Subrouter())
	}

	providers := NewProviders(conf.Providers)
	for _, provider := range providers {
		provider.Mount(r.PathPrefix(PathProviders + "/" + provider.Name()).Subrouter())
	}

	//

	signin := func(w http.ResponseWriter, r *http.Request) {
		session := http.RequestSessionMustGet(r)
		profile := SessionUserProfileGet(session)
		if profile != nil {
			http.Redirect(w, r, paths[PathNameStatus], http.StatusTemporaryRedirect)
			return
		}

		retpath := RequestUserRetpathGet(r)
		if retpath != "" {
			err := RulesMatch(retpath, []Rule(retpathRules)...)
			if err == nil {
				SessionUserRetpathSet(session, retpath)
			} else {
				l := http.RequestLogGet(r)
				l.Warn().
					Str("retpath", retpath).
					Err(err).
					Msg("failed to validate retpath")
			}
		}

		TemplateResponse(
			t.Lookup(string(TemplateNameSignin)),
			http.
				NewTemplateContext(r).
				With(TemplateContextKeySession, session).
				With(TemplateContextKeyPaths, templatePaths).
				With(TemplateContextKeyConnectors, connectors),
			w,
		)
	}

	r.
		HandleFunc(PathRoot, signin).
		Methods(http.MethodGet)
	r.
		HandleFunc(PathSignin, signin).
		Methods(http.MethodGet)
	r.
		HandleFunc(PathSignout, func(w http.ResponseWriter, r *http.Request) {
			SessionUserProfileDel(http.RequestSessionMustGet(r))
			TemplateResponse(
				t.Lookup(string(TemplateNameSignout)),
				http.
					NewTemplateContext(r).
					With(TemplateContextKeyPaths, templatePaths),
				w,
			)
		}).
		Methods(http.MethodPost)

	r.
		HandleFunc(PathStatus, func(w http.ResponseWriter, r *http.Request) {
			session := http.RequestSessionMustGet(r)
      profile := SessionUserProfileGet(session)
      if profile == nil {
        w.WriteHeader(http.StatusUnauthorized)
      }

			TemplateResponse(
				t.Lookup(string(TemplateNameStatus)),
				http.
					NewTemplateContext(r).
					With(TemplateContextKeySession, session).
					With(TemplateContextKeyUserProfile, profile).
					With(TemplateContextKeyPaths, templatePaths).
					With(TemplateContextKeyConnectors, connectors).
					With(TemplateContextKeyProviders, providers),
				w,
			)
		}).
		Methods(http.MethodGet)

	r.
		HandleFunc(PathStatus, func(w http.ResponseWriter, r *http.Request) {
			if SessionUserProfileGet(http.RequestSessionMustGet(r)) == nil {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}).
		Methods(http.MethodHead)
}
