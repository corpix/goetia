package proxy

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/corpix/gdk/crypto"
	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
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
		Jwks crypto.TokenJwtKeySet
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
	c.ProviderOauthConfig.Default()

	for _, key := range OidcHandlerPathNames {
		if _, ok := c.Paths[OauthHandlerPathName(key)]; !ok {
			c.Paths[OauthHandlerPathName(key)] = OauthHandlerPath(OidcHandlerPaths[key])
		}
	}
}

func (c *ProviderOidcConfig) Validate() error {
	for _, k := range []OidcTokenType{
		// NOTE: checked during oauth provider config validation
		// OidcTokenTypeCode,
		// OidcTokenTypeAccess,
		// OidcTokenTypeRefresh,
		OidcTokenTypeId,
	} {
		_, ok := c.Tokens[string(k)]
		if !ok {
			return errors.Errorf("configuration for %q token type is required", k)
		}
	}
	return nil
}

//

func (c *ProviderOidc) Path(name OidcHandlerPathName) string {
	return string(c.Config.Paths[OauthHandlerPathName(name)])
}

func (c *ProviderOidc) Token(discover *ProviderOidcDiscovery, profile *UserProfile, sessionId []byte, app *ProviderOauthApplication) *OidcTokenResponse {
	oauthTokenResp := c.ProviderOauth.Token(sessionId, app)
	idToken := c.TokenService.New(OauthTokenType(OidcTokenTypeId))
	idToken.Header.Meta.Set(crypto.TokenHeaderMapKeyAudience, []string{app.Id()})
	idToken.Header.Meta.Set(crypto.TokenHeaderMapKeyIssuer, discover.Issuer)
	idToken.Header.Meta.Set(crypto.TokenHeaderMapKeySubject, profile.Name)
	idToken.Header.Meta.Set(OidcTokenMapKeyNickname, profile.Name)
	idToken.Header.Meta.Set(OidcTokenMapKeyEmail, profile.Mail)
	idTokenBytes := c.TokenService.MustEncode(OauthTokenType(OidcTokenTypeId), idToken)

	return &OidcTokenResponse{
		OauthTokenResponse: *oauthTokenResp,
		IdToken:            string(idTokenBytes),
	}
}

func (c *ProviderOidc) Mount(router *http.Router) {
	var (
		authorizePath string
		tokenPath     string
		discoveryPath string
		jwksPath      string
	)

	//

	di.MustInvoke(di.Default, func(
		h *http.Http,
		t *template.Template,
		profileRules UserProfileRules,
		paths Paths,
		csrfService *http.CsrfTokenService,
		sessionService *http.SessionService,
		headersService *UserProfileHeadersService,
	) {
		discovery := func(r *http.Request) *ProviderOidcDiscovery {
			return &ProviderOidcDiscovery{
				Issuer: h.Url(r.URL, func(u *url.URL) {
					u.Host = r.Host
					u.Path = "/"
				}).String(),
				AuthorizationEndpoint: h.Url(r.URL, func(u *url.URL) {
					u.Host = r.Host
					u.Path = authorizePath
				}).String(),
				TokenEndpoint: h.Url(r.URL, func(u *url.URL) {
					u.Host = r.Host
					u.Path = tokenPath
				}).String(),
				JwksUri: h.Url(r.URL, func(u *url.URL) {
					u.Host = r.Host
					u.Path = jwksPath
				}).String(),
			}
		}

		router.
			HandleFunc(c.Path(OidcHandlerPathNameDiscovery), func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(http.HeaderContentType, http.MimeTextJson)

				err := json.NewEncoder(w).Encode(discovery(r))
				if err != nil {
					panic(err)
				}
			}).
			Name(string(OidcHandlerPathNameDiscovery)).
			Methods(http.MethodGet)

		router.
			HandleFunc(c.Path(OidcHandlerPathNameJwks), func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(http.HeaderContentType, http.MimeTextJson)

				err := json.NewEncoder(w).Encode(c.Jwks)
				if err != nil {
					panic(err)
				}
			}).
			Name(string(OidcHandlerPathNameJwks)).
			Methods(http.MethodGet)

		router.
			HandleFunc(c.Path(OidcHandlerPathNameToken), func(w http.ResponseWriter, r *http.Request) {
				sessionId, app := c.CodeLoad(r)
				session, err := sessionService.Store.Load(sessionId)
				if err != nil {
					panic(err)
				}
				resBytes, err := json.Marshal(c.Token(
					discovery(r),
					SessionUserProfileGet(session),
					sessionId,
					app,
				))
				if err != nil {
					panic(err)
				}

				w.WriteHeader(http.StatusOK)
				w.Header().Set(http.HeaderContentType, http.MimeTextJson)
				w.Write(resBytes)
			}).
			Name(string(OidcHandlerPathNameToken)).
			Methods(http.MethodPost)

		// NOTE: registering routes after because:
		// for some reason registering same route does not override existing (sic!)
		c.ProviderOauth.Mount(router)

		//

		authorizePath = http.RoutePathTemplate(router, OidcHandlerPathNameAuthorize)
		tokenPath = http.RoutePathTemplate(router, OidcHandlerPathNameToken)
		discoveryPath = http.RoutePathTemplate(router, OidcHandlerPathNameDiscovery)
		jwksPath = http.RoutePathTemplate(router, OidcHandlerPathNameJwks)

		csrfService.SkipPaths(discoveryPath, jwksPath)
		sessionService.SkipPaths(discoveryPath, jwksPath)
		headersService.SkipPaths(discoveryPath, jwksPath)
	})
}

func NewProviderOidc(c *ProviderOidcConfig) *ProviderOidc {
	oauthProvider := NewProviderOauth(c.ProviderOauthConfig)
	tokenKeys := make([]*crypto.TokenJwtKey, len(oauthProvider.TokenService))

	n := 0
	for _, s := range oauthProvider.TokenService {
		if _, ok := s.Container.(*crypto.TokenContainerJwt); !ok {
			panic(fmt.Sprintf(
				"found non JWT token type for %q, OIDC is working only with JWT tokens",
				s.Type,
			))
		}
		if !s.Container.Cap().Has(crypto.TokenCapPubKeyCrypto) {
			panic(fmt.Sprintf(
				"found token %q not using public key cryptography, OIDC requires public key cryptography",
				s.Type,
			))
		}

		tokenKeys[n] = s.Container.(*crypto.TokenContainerJwt).Key
		n++
	}

	provider := &ProviderOidc{
		ProviderOauth: oauthProvider,
		Jwks:          crypto.TokenJwtKeySet{Keys: tokenKeys},
	}
	return provider
}

func NewProviderOidcApplication(name string, c *ProviderOidcApplicationConfig) *ProviderOidcApplication {
	return &ProviderOidcApplication{
		id:     name,
		Config: c,
	}
}
