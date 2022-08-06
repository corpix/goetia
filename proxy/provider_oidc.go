package proxy

import (
	"encoding/json"
	"net/url"

	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/template"
)

type (
	ProviderOidcConfig struct {
		*ProviderOauthConfig `yaml:",inline"`
	}
	ProviderOidcApplicationConfig = ProviderOauthApplicationConfig
	ProviderOidcApplication       = ProviderOauthApplication
	ProviderOidc                  struct {
		*ProviderOauth
	}
	ProviderOidcDiscovery struct {
		Issuer                            string   `json:"issuer,omitempty"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
		TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
		UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
		JwksUri                           string   `json:"jwks_uri,omitempty"`
		ScopesSupported                   []string `json:"scopes_supported,omitempty"`
		ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	}
)

//

func (c *ProviderOidcConfig) Default() {
	if c.ProviderOauthConfig == nil {
		c.ProviderOauthConfig = &ProviderOauthConfig{}
	}
	if c.ProviderOauthConfig.Name == "" {
		c.ProviderOauthConfig.Name = string(ProviderNameOidc)
	}
	if c.ProviderOauthConfig.Label == "" {
		c.ProviderOauthConfig.Label = "OIDC"
	}
	if c.ProviderOauthConfig.Description == "" {
		c.ProviderOauthConfig.Description = "OIDC provider"
	}
}

//

func (c *ProviderOidc) Mount(router *http.Router) {
	c.ProviderOauth.Mount(router)

	authorizePath, err := router.Get(string(OauthHandlerPathAuthorize)).GetPathTemplate()
	if err != nil {
		panic(err)
	}

	//

	di.MustInvoke(di.Default, func(
		h *http.Http,
		t *template.Template,
		profileRules UserProfileRules,
		paths Paths,
		sessionService *http.SessionService,
	) {
		router.
			HandleFunc(string(OidcHandlerPathDiscovery), func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(http.HeaderContentType, http.MimeTextJson)

				err := json.NewEncoder(w).Encode(&ProviderOidcDiscovery{
					Issuer: h.Url(r.URL, func(u *url.URL) {
						u.Host = r.Host
						u.Path = "/"
					}).String(),
					AuthorizationEndpoint: h.Url(r.URL, func(u *url.URL) {
						u.Host = r.Host
						u.Path = authorizePath
					}).String(),
					//TokenEndpoint: string,
				})
				if err != nil {
					panic(err)
				}
			}).
			Methods(http.MethodGet)

		// router.
		// 	HandleFunc(OidcHandlerPathRedeem, func(w http.ResponseWriter, r *http.Request) {
		// 		clientID := ctx.FormValue(OauthParamClientID)
		// 		n, ok := appIndex[clientID]
		// 		if !ok {
		// 			return NewError(
		// 				server.StatusForbidden,
		// 				authorizationError,
		// 				errors.Errorf("no configured application for client-id %q", clientID),
		// 				nil,
		// 			)
		// 		}

		// 		app := p.config.Applications[n]

		// 		//

		// 		userSession := session.MustGetStore(ctx).Session()
		// 		code := NewOauthCode(*app, userSession.Encoder(), p.rand)

		// 		box, err := code.Unpack(ctx.FormValue(OauthParamCode))
		// 		if err != nil {
		// 			return NewError(
		// 				server.StatusForbidden,
		// 				authorizationError,
		// 				err, nil,
		// 			)
		// 		}

		// 		err = code.Validate(box)
		// 		if err != nil {
		// 			return NewError(
		// 				server.StatusForbidden,
		// 				authorizationError,
		// 				errors.Wrap(err, "failed to validate oidc code"),
		// 				nil,
		// 			)
		// 		}

		// 		// FIXME: clone session, we really don't want to have side-effect
		// 		// on real user session here (but this page is not for users, so fine for now)

		// 		profileBytes, ok := box.Get(OauthCodeUserKey)
		// 		if !ok {
		// 			return NewError(
		// 				server.StatusForbidden,
		// 				authorizationError,
		// 				OauthCodeNoUserProfileErr,
		// 				nil,
		// 			)
		// 		}

		// 		userSession.Set(SessionUserKey, profileBytes)

		// 		token, err := userSession.Save()
		// 		if err != nil {
		// 			return NewError(
		// 				server.StatusForbidden,
		// 				authorizationError,
		// 				OauthCodeNoUserProfileErr,
		// 				nil,
		// 			)
		// 		}

		// 		return ctx.JSON(server.StatusOK, OauthToken{
		// 			Token: string(token),
		// 		})
		// 	}).
		// 	Methods(http.MethodPost)

		// router.
		// 	HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 		var err error
		// 		session := http.RequestSessionMustGet(r)

		// 		profile := SessionUserProfileGet(session)
		// 		if profile == nil {
		// 			profile, err = c.Authorize(r)
		// 			if err != nil {
		// 				if errors.Is(err, ErrAuthorizationRequired) {
		// 					w.WriteHeader(http.StatusUnauthorized)
		// 					w.Header().Set(
		// 						http.HeaderWwwAuthenticate,
		// 						http.AuthTypeOauth+" realm="+c.Config.Realm,
		// 					)
		// 					return
		// 				}
		// 				panic(err)
		// 			}

		// 			SessionUserProfileSet(session, profile, []Rule(pr)...)
		// 			Retpath(w, r, ps[PathNameStatus])
		// 		}
		// 	}).
		// 	Methods(http.MethodPost)
	})
}

func NewProviderOidc(c *ProviderOidcConfig) *ProviderOidc {
	provider := &ProviderOidc{
		ProviderOauth: NewProviderOauth(c.ProviderOauthConfig),
	}
	return provider
}

func NewProviderOidcApplication(name string, c *ProviderOidcApplicationConfig) *ProviderOidcApplication {
	return &ProviderOidcApplication{
		id:   name,
		Config: c,
	}
}
