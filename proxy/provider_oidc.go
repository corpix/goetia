package proxy

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/corpix/gdk/crypto"
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

//

func (c *ProviderOidc) Path(name OidcHandlerPathName) string {
	return string(c.Config.Paths[OauthHandlerPathName(name)])
}

func (c *ProviderOidc) Mount(router *http.Router) {
	c.ProviderOauth.Mount(router)

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
		router.
			HandleFunc(c.Path(OidcHandlerPathNameDiscovery), func(w http.ResponseWriter, r *http.Request) {
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
					TokenEndpoint: h.Url(r.URL, func(u *url.URL) {
						u.Host = r.Host
						u.Path = tokenPath
					}).String(),
					JwksUri: h.Url(r.URL, func(u *url.URL) {
						u.Host = r.Host
						u.Path = jwksPath
					}).String(),
				})
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
