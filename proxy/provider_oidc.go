package proxy

import (
	"encoding/json"
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
    tokenPath string
    jwksPath string
  )

	//

	di.MustInvoke(di.Default, func(
		h *http.Http,
		t *template.Template,
		profileRules UserProfileRules,
		paths Paths,
		sessionService *http.SessionService,
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
      HandleFunc(c.Path(OidcHandlerPathNameJwks), func(http.ResponseWriter, *http.Request) {

      }).
      Name(string(OidcHandlerPathNameJwks)).
      Methods(http.MethodGet)

    //

    authorizePath = RoutePathTemplate(router, OidcHandlerPathNameAuthorize)
    tokenPath = RoutePathTemplate(router, OidcHandlerPathNameToken)
    jwksPath = RoutePathTemplate(router, OidcHandlerPathNameJwks)
	})
}

func NewProviderOidc(c *ProviderOidcConfig) *ProviderOidc {
  oauthProvider := NewProviderOauth(c.ProviderOauthConfig)
  if !oauthProvider.TokenService.Container.Cap().Has(crypto.TokenCapPubKeyCrypto) {
    panic("token container does not have public key cryptography capability, probably you use shared secret signature scheme which is not capable to serve OIDC needs, switch to JWT with ES512 or something")
  }
	provider := &ProviderOidc{
		ProviderOauth: oauthProvider,
	}
	return provider
}

func NewProviderOidcApplication(name string, c *ProviderOidcApplicationConfig) *ProviderOidcApplication {
	return &ProviderOidcApplication{
		id:   name,
		Config: c,
	}
}
