package proxy

import (
	"encoding/json"
	"io/ioutil"
	"net/url"

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

		Token        *OauthTokenConfig                          `yaml:"token"`
		Applications map[string]*ProviderOauthApplicationConfig `yaml:"applications"`
	}
	ProviderOauth struct {
		Config       *ProviderOauthConfig
		TokenService *OauthTokenService
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
		id     string
		Config *ProviderOauthApplicationConfig
	}
	ProviderOauthApplicationProfileConfig struct {
		Map map[string]string `yaml:"map"`
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
	if c.Token == nil {
		c.Token = &OauthTokenConfig{}
	}
	if c.Applications == nil {
		c.Applications = map[string]*ProviderOauthApplicationConfig{}
	}
	for name, app := range c.Applications {
		if app.Label == "" {
			app.Label = name
		}
	}
}

func (c *ProviderOauthConfig) Validate() error {
	if len(c.Applications) == 0 {
		return errors.New("one or more applications should be defined")
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
	if c.Key == "" && c.KeyFile == "" {
		return errors.New("either key or key-file should be defined")
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

//

func (a *ProviderOauthApplication) Id() string {
	return a.id
}

func (a *ProviderOauthApplication) Label() string {
	return a.Config.Label
}

func (a *ProviderOauthApplication) RediretUri() *url.URL {
	return a.Config.redirectUri
}

//

func (c *ProviderOauth) GetToken(tokenType OauthTokenType, tokenBytes []byte) (*OauthToken, error) {
	token, err := c.TokenService.Decode(tokenBytes)
	if err != nil {
		return nil, err
	}
	err = c.TokenService.Validate(tokenType, token)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (c *ProviderOauth) GetSessionId(token *OauthToken) ([]byte, error) {
	sessionId, ok := token.GetString(string(OauthTokenPayloadKeySessionId))
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

//

func (c *ProviderOauth) Name() string        { return c.Config.Name }
func (c *ProviderOauth) Label() string       { return c.Config.Label }
func (c *ProviderOauth) Description() string { return c.Config.Description }

func (c *ProviderOauth) Mount(router *http.Router) {
	di.MustInvoke(di.Default, func(
		t *template.Template,
		profileRules UserProfileRules,
		paths Paths,
		sessionService *http.SessionService,
	) {
		templatePaths := paths.TemplateContext()

		router.
			HandleFunc(string(OauthHandlerPathAuthorize), func(w http.ResponseWriter, r *http.Request) {
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
			Name(string(OauthHandlerPathAuthorize)).
			Methods(http.MethodGet)

		router.
			HandleFunc(string(OauthHandlerPathAuthorize), func(w http.ResponseWriter, r *http.Request) {
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

				sessionId, err := sessionService.Store.Id(r)
				if err != nil {
					panic(err)
				}

				rq := r.URL.Query()
				requestedRedirectUri := rq.Get(string(OauthParameterRedirectUri))
				configuredRedirectUri := app.RediretUri().String()
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
				code.Set(string(OauthTokenPayloadKeyApplicationId), app.Id())
				code.Set(string(OauthTokenPayloadKeySessionId), string(sessionId))

				codeBytes := c.TokenService.MustEncode(code)

				//

				u := *app.RediretUri()
				q := u.Query()
				if state := rq.Get(string(OauthParameterState)); state != "" {
					// TODO: should we yell on the empty state query param?
					q.Set(string(OauthParameterState), state)
				}
				q.Set(string(OauthParameterCode), string(codeBytes))
				u.RawQuery = q.Encode()

				//

				http.Redirect(w, r, u.String(), http.StatusFound)
			}).
			Methods(http.MethodPost)

		router.
			HandleFunc(string(OauthHandlerPathToken), func(w http.ResponseWriter, r *http.Request) {
				err := r.ParseForm()
				if err != nil {
					panic(err)
				}

				app, err := c.Application(r.Form)
				if err != nil {
					panic(err)
				}

				//

				code, err := c.GetToken(OauthTokenTypeCode, []byte(r.Form.Get(string(OauthParameterCode))))
				if err != nil {
					panic(err)
				}
				sessionId, err := c.GetSessionId(code)
				if err != nil {
					panic(err)
				}

				token := c.TokenService.New(OauthTokenTypeAccess)
				token.Set(string(OauthTokenPayloadKeyApplicationId), app.Id())
				token.Set(string(OauthTokenPayloadKeySessionId), string(sessionId))
				tokenBytes := c.TokenService.MustEncode(token)

				resBytes, err := json.Marshal(struct {
					Token string `json:"access_token"`
					Type  string `json:"token_type"`
				}{
					Token: string(tokenBytes),
					Type:  string(OauthTokenTypeAccess),
				})
				if err != nil {
					panic(err)
				}

				w.WriteHeader(http.StatusOK)
				w.Header().Set(http.HeaderContentType, http.MimeTextJson)
				w.Write(resBytes)
			}).
			Name(string(OauthHandlerPathToken)).
			Methods(http.MethodPost)

		router.
			HandleFunc(string(OauthHandlerPathProfile), func(w http.ResponseWriter, r *http.Request) {
				token, err := c.GetToken(OauthTokenTypeAccess, []byte(r.Header.Get(http.HeaderAuthorization)))
				if err != nil {
					panic(err)
				}
        app, err := c.ApplicationById(token.MustGetString(string(OauthTokenPayloadKeyApplicationId)))
				if err != nil {
					panic(err)
				}

				session, err := c.GetSession(sessionService, token)
				if err != nil {
					panic(err)
				}

				profile := SessionUserProfileGet(session).Remap(app.Config.Profile.Map)
				resBytes, err := json.Marshal(profile)
				if err != nil {
					panic(err)
				}

				w.WriteHeader(http.StatusOK)
				w.Header().Set(http.HeaderContentType, http.MimeTextJson)
				w.Write(resBytes)
			}).
			Name(string(OauthHandlerPathProfile)).
			Methods(http.MethodGet)

		router.
			HandleFunc(string(OauthHandlerPathValidate), func(w http.ResponseWriter, r *http.Request) {
				token, err := c.GetToken(OauthTokenTypeAccess, []byte(r.Header.Get(http.HeaderAuthorization)))
				if err != nil {
					panic(err)
				}
				_, err = c.GetSession(sessionService, token)
				if err != nil {
					panic(err)
				}

				w.WriteHeader(http.StatusOK)
			}).
			Name(string(OauthHandlerPathValidate)).
			Methods(http.MethodGet)
	})
}

func NewProviderOauth(c *ProviderOauthConfig) *ProviderOauth {
	provider := &ProviderOauth{
		Config:       c,
		TokenService: NewOauthTokenService(c.Token),
		Applications: map[string]*ProviderOauthApplication{},
	}

	for name, conf := range c.Applications {
		provider.Applications[name] = NewProviderOauthApplication(name, conf)
	}

	return provider
}

func NewProviderOauthApplication(id string, c *ProviderOauthApplicationConfig) *ProviderOauthApplication {
	return &ProviderOauthApplication{
		id:     id,
		Config: c,
	}
}
