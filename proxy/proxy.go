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
		Enable []string `yaml:"enable"`
		// Slack  *ConnectorSlackConfig  `yaml:"slack"`
		// Oidc   *ConnectorOidcConfig   `yaml:"oidc"`
		Basic *ConnectorBasicConfig `yaml:"basic"`
		// Bypass *ConnectorBypassConfig `yaml:"bypass"`
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
		Enable []string `yaml:"enable"`
		// Oauth  *ProviderOauthConfig `yaml:"oauth"`
	}
	ProviderName string
	Provider     interface {
		Name() string
		Label() string
		Description() string
		Mount(*http.Router)
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

	// ConnectorNameSlack  ConnectorName = "slack"
	// ConnectorNameOidc   ConnectorName = "oidc"
	ConnectorNameBasic ConnectorName = "basic"
	// ConnectorNameBypass ConnectorName = "bypass"

	// ProviderNameOauth ProviderName = "oauth"
)

var (
	ConnectorNames = map[string]struct{}{
		// string(ConnectorNameSlack):  {},
		// string(ConnectorNameOidc):   {},
		string(ConnectorNameBasic): {},
		// string(ConnectorNameBypass): {},
	}

	// _ Connector = &ConnectorSlack{}
	// _ Connector = &ConnectorOidc{}
	_ Connector = &ConnectorBasic{}
	// _ Connector = &ConnectorBypass{}

	ProviderNames = map[string]struct{}{
		// string(ProviderNameOauth): {},
	}

	// _ Provider = &ProviderOauth{}

	ErrAuthorizationRequired = errors.New("authorization required")
)

//

func (p Paths) TemplateContext() TemplateContext {
	ctx := make(TemplateContext, len(p))
	for k, v := range p {
		ctx[string(k)] = v
	}
	return ctx
}

func NewPaths(prefix string) Paths {
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

	// if c.Slack == nil && enabled[ConenctorNameSlack] {
	// 	c.Slack = &ConnectorSlackConfig{}
	// }
	// if c.Oidc == nil && enabled[ConnectorNameOidc] {
	// 	c.Oidc = &ConnectorOidcConfig{}
	// }
	if c.Basic == nil && enabled[ConnectorNameBasic] {
		c.Basic = &ConnectorBasicConfig{}
	}
	// if c.Bypass == nil && enabled[ConnectorNameBypass] {
	// 	c.Bypass = &ConnectorBypassConfig{}
	// }
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

	// if c.Oauth == nil && enabled[ProviderNameOauth] {
	// 	c.Oauth = &ProviderOauthConfig{}
	// }

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

func NewConnectors(c *ConnectorsConfig, p Paths) []Connector {
	connectors := make([]Connector, len(c.Enable))
	for n, name := range c.Enable {
		switch ConnectorName(name) {
		// case ConnectorNameSlack:
		// case ConnectorNameOidc:
		case ConnectorNameBasic:
			connectors[n] = NewConnectorBasic(c.Basic, p)
			// case ConnectorNameBypass:
		}
	}
	return connectors
}

func NewProviders(c *ProvidersConfig, p Paths) []Provider {
	providers := make([]Provider, len(c.Enable))
	for n, name := range c.Enable {
		_ = n
		switch ProviderName(name) {
		// case ProviderNameOauth:
		//   providers[n] = NewProviderOauth(c.Oauth, p)
		}
	}
	return providers
}

func ErrorHandlerCtr(t *template.Template) http.RecoverHandler {
	errTemplate := t.Lookup(string(TemplateNameError))
	return func(w http.ResponseWriter, r *http.Request, err error) {
		TemplateResponse(
			errTemplate,
			http.
				NewTemplateContext(r).
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
		h.Router.Use(MiddlewareUserProfileHeaders(conf.User.Profile.Headers))
	}

	//

	paths := NewPaths(conf.Prefix)
	templatePaths := paths.TemplateContext()
	retpathRules := NewUserProfileRetpathRules(conf.User.Retpath.Rules)
	userProfileRules := NewUserProfileRules(conf.User.Profile.Rules)

	//

	di.MustProvide(di.Default, func() UserProfileRetpathRules { return retpathRules })
	di.MustProvide(di.Default, func() UserProfileRules { return userProfileRules })

	//

	connectors := NewConnectors(conf.Connectors, paths)
	for _, connector := range connectors {
		connector.Mount(r)
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
			TemplateResponse(
				t.Lookup(string(TemplateNameStatus)),
				http.
					NewTemplateContext(r).
					With(TemplateContextKeySession, session).
					With(TemplateContextKeyUserProfile, SessionUserProfileGet(session)).
					With(TemplateContextKeyPaths, templatePaths).
					With(TemplateContextKeyConnectors, connectors),
				w,
			)
		}).
		Methods(http.MethodGet)
}
