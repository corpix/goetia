package proxy

import (
	"encoding/json"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/itchyny/gojq"

	"github.com/corpix/gdk/crypto"
	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/template"
)

type (
	ProviderOauthConfig struct {
		Name        string `yaml:"name"`
		Label       string `yaml:"label"`
		Description string `yaml:"description"`

		Tokens       OauthTokenConfigs                          `yaml:"tokens"`
		Applications map[string]*ProviderOauthApplicationConfig `yaml:"applications"`
		Paths        map[OauthHandlerPathName]OauthHandlerPath  `yaml:"paths"`
	}
	ProviderOauth struct {
		Config       *ProviderOauthConfig
		TokenService OauthTokenService
		Applications map[string]*ProviderOauthApplication
	}

	ProviderOauthApplicationConfig struct {
		Label       string                                 `yaml:"label"`
		Key         string                                 `yaml:"key"`
		KeyFile     string                                 `yaml:"key-file"`
		RedirectUri string                                 `yaml:"redirect-uri"`
		Profile     *ProviderOauthApplicationProfileConfig `yaml:"profile"`

		key         string
		redirectUri *url.URL
	}
	ProviderOauthApplication struct {
		Config *ProviderOauthApplicationConfig

		id string
	}
	ProviderOauthApplicationProfileConfig struct {
		Map        map[string]string `yaml:"map"`
		ExpandExpr string            `yaml:"expand"`

		expandExpr *gojq.Query
	}
)

func (c *ProviderOauthConfig) Default() {
	if c.Name == "" {
		c.Name = string(ProviderNameOauth)
	}
	if c.Label == "" {
		c.Label = "OAuth2"
	}
	if c.Description == "" {
		c.Description = "OAuth2 provider"
	}
	if len(c.Tokens) == 0 {
		c.Tokens = OauthTokenConfigs{}
	}
	if c.Applications == nil {
		c.Applications = map[string]*ProviderOauthApplicationConfig{}
	}
	for name, app := range c.Applications {
		if app.Label == "" {
			app.Label = name
		}
	}
	if c.Paths == nil {
		c.Paths = map[OauthHandlerPathName]OauthHandlerPath{}
	}
	for _, key := range OauthHandlerPathNames {
		if _, ok := c.Paths[key]; !ok {
			c.Paths[key] = OauthHandlerPaths[key]
		}
	}
}

func (c *ProviderOauthConfig) Validate() error {
	if len(c.Applications) == 0 {
		return errors.New("one or more applications should be defined")
	}
	for k, v := range c.Paths {
		if len(v) == 0 {
			return errors.Errorf("path %q should not be empty", k)
		}
	}
	for _, k := range []OauthTokenType{
		OauthTokenTypeCode,
		OauthTokenTypeAccess,
		OauthTokenTypeRefresh,
	} {
		_, ok := c.Tokens[string(k)]
		if !ok {
			return errors.Errorf("configuration for %q token type is required", k)
		}
	}
	return nil
}

func (c *ProviderOauthConfig) Expand() error {
	for k, v := range c.Paths {
		if v[0] != '/' {
			c.Paths[k] = "/" + v
		}
	}
	return nil
}

//

func (c *ProviderOauthApplicationConfig) Default() {
	if c.Profile == nil {
		c.Profile = &ProviderOauthApplicationProfileConfig{}
	}
}

func (c *ProviderOauthApplicationConfig) Validate() error {
	if c.Key != "" && c.KeyFile != "" {
		return errors.New("either key or key-file should be defined, not both")
	}
	if c.RedirectUri == "" {
		return errors.New("redirect-uri should not be empty")
	}
	return nil
}

func (c *ProviderOauthApplicationConfig) Expand() error {
	if c.KeyFile != "" {
		key, err := ioutil.ReadFile(c.KeyFile)
		if err != nil {
			return err
		}
		c.key = string(key)
	} else {
		c.key = c.Key
	}

	u, err := url.Parse(c.RedirectUri)
	if err != nil {
		return err
	}
	c.redirectUri = u
	return nil
}

func (c *ProviderOauthApplicationProfileConfig) Default() {
	if c.Map == nil {
		c.Map = map[string]string{}
	}
	for _, key := range UserProfileKeys {
		_, ok := c.Map[key]
		if !ok {
			c.Map[key] = key
		}
	}
}

func (c *ProviderOauthApplicationProfileConfig) Expand() error {
	if c.ExpandExpr != "" {
		expr, err := gojq.Parse(c.ExpandExpr)
		if err != nil {
			return err
		}
		c.expandExpr = expr
	}
	return nil
}

//

func (a *ProviderOauthApplication) Id() string {
	return a.id
}

func (a *ProviderOauthApplication) Label() string {
	return a.Config.Label
}

func (a *ProviderOauthApplication) RedirectUri() *url.URL {
	return a.Config.redirectUri
}

func (a *ProviderOauthApplication) UserProfileExpandRemap(profile *UserProfile) map[string]interface{} {
	m := profile.Map()
	rm := UserProfileRemap(m, a.Config.Profile.Map)
	if a.Config.Profile.expandExpr == nil {
		return rm
	}
	return UserProfileExpand(rm, a.Config.Profile.expandExpr)
}

//

func (c *ProviderOauth) GetToken(typ OauthTokenType, rawToken []byte) (*OauthToken, error) {
	token, err := c.TokenService.Decode(typ, rawToken)
	if err != nil {
		return nil, err
	}
	err = c.TokenService.Validate(typ, token)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (c *ProviderOauth) GetSessionId(token *OauthToken) ([]byte, error) {
	sessionId, ok := token.GetString(OauthTokenMapKeySessionId)
	if !ok {
		return nil, errors.New("no session id inside code token")
	}
	// NOTE: rawSessionId is string to prevent base64 encoding of the value by marshalers
	return []byte(sessionId), nil
}

func (c *ProviderOauth) GetSession(sessionService *http.SessionService, token *OauthToken) (*http.Session, error) {
	sessionId, err := c.GetSessionId(token)
	if err != nil {
		return nil, err
	}
	session, err := sessionService.Store.Load(sessionId)
	if err != nil {
		return nil, err
	}
	err = sessionService.Validate(session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (c *ProviderOauth) ApplicationById(id string) (*ProviderOauthApplication, error) {
	app, ok := c.Applications[id]
	if !ok {
		return nil, errors.Errorf("application with id %q does not exists", id)
	}
	return app, nil
}

func (c *ProviderOauth) Application(kv KeyValue) (*ProviderOauthApplication, error) {
	return c.ApplicationById(kv.Get(string(OauthParameterClientId)))
}

func (c *ProviderOauth) Path(name OauthHandlerPathName) string {
	return string(c.Config.Paths[name])
}

//

func (c *ProviderOauth) Name() string        { return c.Config.Name }
func (c *ProviderOauth) Label() string       { return c.Config.Label }
func (c *ProviderOauth) Description() string { return c.Config.Description }

func (c *ProviderOauth) splitAuthToken(h http.Header) []byte {
	tokenStr := h.Get(http.HeaderAuthorization)
	tokenParts := strings.SplitN(tokenStr, " ", 2)
	return []byte(tokenParts[len(tokenParts)-1])
}

func (c *ProviderOauth) CodeUrl(sessionId []byte, w http.ResponseWriter, r *http.Request) *url.URL {
	app, err := c.Application(r.URL.Query())
	if err != nil {
		panic(err)
	}

	rq := r.URL.Query()
	requestedRedirectUri := rq.Get(string(OauthParameterRedirectUri))
	configuredRedirectUri := app.RedirectUri().String()
	if requestedRedirectUri != configuredRedirectUri {
		panic(errors.Errorf(
			"application %q requested redirect uri %q does not match configured %q",
			app.Id(),
			requestedRedirectUri,
			configuredRedirectUri,
		))
	}

	//

	code := c.TokenService.New(OauthTokenTypeCode)
	// NOTE: sessionId must be string here, otherwise
	// it might be base64 encoded encoded by subsequent marshaler
	code.Set(OauthTokenMapKeyApplicationId, app.Id())
	code.Set(OauthTokenMapKeySessionId, string(sessionId))

	codeBytes := c.TokenService.MustEncode(OauthTokenTypeCode, code)

	//

	u := *app.RedirectUri()
	q := u.Query()
	if state := rq.Get(string(OauthParameterState)); state != "" {
		// TODO: should we yell on the empty state query param?
		q.Set(string(OauthParameterState), state)
	}
	q.Set(string(OauthParameterCode), string(codeBytes))
	u.RawQuery = q.Encode()

	return &u
}

func (c *ProviderOauth) Code(r *http.Request) *OauthToken {
	err := r.ParseForm()
	if err != nil {
		panic(err)
	}

	code, err := c.GetToken(OauthTokenTypeCode, []byte(r.Form.Get(string(OauthParameterCode))))
	if err != nil {
		panic(err)
	}
	return code
}

func (c *ProviderOauth) Token(sessionId []byte, app *ProviderOauthApplication) *OauthTokenResponse {
	appId := app.Id()
	audience := []string{appId}

	//

	accessToken := c.TokenService.New(OauthTokenTypeAccess)
	accessToken.Header.Meta.Set(crypto.TokenHeaderMapKeyAudience, audience)
	accessToken.Set(OauthTokenMapKeyApplicationId, appId)
	accessToken.Set(OauthTokenMapKeySessionId, string(sessionId))
	accessTokenBytes := c.TokenService.MustEncode(OauthTokenTypeAccess, accessToken)

	refreshToken := c.TokenService.New(OauthTokenTypeRefresh)
	refreshToken.Header.Meta.Set(crypto.TokenHeaderMapKeyAudience, audience)
	refreshToken.Set(OauthTokenMapKeyApplicationId, appId)
	refreshToken.Set(OauthTokenMapKeySessionId, string(sessionId))
	refreshTokenBytes := c.TokenService.MustEncode(OauthTokenTypeRefresh, refreshToken)

	return &OauthTokenResponse{
		AccessToken:  string(accessTokenBytes),
		RefreshToken: string(refreshTokenBytes),
		Type:         string(OauthTokenTypeAccess),
	}
}

func (c *ProviderOauth) Mount(router *http.Router) {
	di.MustInvoke(di.Default, func(
		t *template.Template,
		profileRules UserProfileRules,
		paths Paths,
		csrfService *http.CsrfTokenService,
		sessionService *http.SessionService,
		headersService *UserProfileHeadersService,
	) {
		var (
			tokenPath   string
			profilePath string
		)

		templatePaths := paths.TemplateContext()

		router.
			HandleFunc(c.Path(OauthHandlerPathNameAuthorize), func(w http.ResponseWriter, r *http.Request) {
				session := http.RequestSessionMustGet(r)
				profile := SessionUserProfileGetOrRedirect(w, r, session, paths[PathNameSignin])
				if profile == nil {
					return
				}

				//

				app, err := c.Application(r.URL.Query())
				if err != nil {
					panic(err)
				}

				TemplateResponse(
					t.Lookup(string(TemplateNameAuthorize)),
					http.
						NewTemplateContext(r).
						With(TemplateContextKeySession, session).
						With(TemplateContextKeyPaths, templatePaths).
						With(TemplateContextKeyUserProfile, profile).
						With(TemplateContextKeyProvider, c).
						With(TemplateContextKeyProviderApplication, app),
					w,
				)
			}).
			Name(string(OauthHandlerPathNameAuthorize)).
			Methods(http.MethodGet)

		router.
			HandleFunc(c.Path(OauthHandlerPathNameAuthorize), func(w http.ResponseWriter, r *http.Request) {
				session := http.RequestSessionMustGet(r)
				profile := SessionUserProfileGetOrRedirect(w, r, session, paths[PathNameSignin])
				if profile == nil {
					return
				}
				sessionId, err := sessionService.Store.Id(r)
				if err != nil {
					panic(err)
				}

				http.Redirect(w, r, c.CodeUrl(sessionId, w, r).String(), http.StatusFound)
			}).
			Methods(http.MethodPost)

		router.
			HandleFunc(c.Path(OauthHandlerPathNameToken), func(w http.ResponseWriter, r *http.Request) {
				code := c.Code(r)
				sessionId, err := c.GetSessionId(code)
				if err != nil {
					panic(err)
				}
				app, err := c.ApplicationById(code.MustGetString(OauthTokenMapKeyApplicationId))
				if err != nil {
					panic(err)
				}

				resBytes, err := json.Marshal(c.Token(sessionId, app))
				if err != nil {
					panic(err)
				}

				w.WriteHeader(http.StatusOK)
				w.Header().Set(http.HeaderContentType, http.MimeTextJson)
				w.Write(resBytes)
			}).
			Name(string(OauthHandlerPathNameToken)).
			Methods(http.MethodPost)

		router.
			HandleFunc(c.Path(OauthHandlerPathNameProfile), func(w http.ResponseWriter, r *http.Request) {
				token, err := c.GetToken(OauthTokenTypeAccess, c.splitAuthToken(r.Header))
				if err != nil {
					panic(err)
				}
				app, err := c.ApplicationById(token.MustGetString(OauthTokenMapKeyApplicationId))
				if err != nil {
					panic(err)
				}

				session, err := c.GetSession(sessionService, token)
				if err != nil {
					panic(err)
				}

				profile := app.UserProfileExpandRemap(SessionUserProfileGet(session))
				resBytes, err := json.Marshal(profile)
				if err != nil {
					panic(err)
				}

				w.WriteHeader(http.StatusOK)
				w.Header().Set(http.HeaderContentType, http.MimeTextJson)
				w.Write(resBytes)
			}).
			Name(string(OauthHandlerPathNameProfile)).
			Methods(http.MethodGet)

		router.
			HandleFunc(c.Path(OauthHandlerPathNameValidate), func(w http.ResponseWriter, r *http.Request) {
				token, err := c.GetToken(OauthTokenTypeAccess, c.splitAuthToken(r.Header))
				if err != nil {
					panic(err)
				}
				_, err = c.GetSession(sessionService, token)
				if err != nil {
					panic(err)
				}

				w.WriteHeader(http.StatusOK)
			}).
			Name(string(OauthHandlerPathNameValidate)).
			Methods(http.MethodGet)

		tokenPath = http.RoutePathTemplate(router, OauthHandlerPathNameToken)
		profilePath = http.RoutePathTemplate(router, OauthHandlerPathNameProfile)

		csrfService.SkipPaths(tokenPath, profilePath)
		sessionService.SkipPaths(tokenPath, profilePath)
		headersService.SkipPaths(tokenPath, profilePath)
	})
}

func NewProviderOauth(c *ProviderOauthConfig) *ProviderOauth {
	provider := &ProviderOauth{
		Config:       c,
		TokenService: NewOauthTokenService(c.Tokens),
		Applications: map[string]*ProviderOauthApplication{},
	}

	for name, conf := range c.Applications {
		provider.Applications[name] = NewProviderOauthApplication(name, conf)
	}

	return provider
}

func NewProviderOauthApplication(id string, c *ProviderOauthApplicationConfig) *ProviderOauthApplication {
	return &ProviderOauthApplication{
		Config: c,
		id:     id,
	}
}
