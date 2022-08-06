package proxy

type (
	OidcHandlerPath string
)

const (
	OidcHandlerPathAuthorize OidcHandlerPath = OidcHandlerPath(OauthHandlerPathAuthorize)
	OidcHandlerPathToken     OidcHandlerPath = OidcHandlerPath(OauthHandlerPathToken)
	OidcHandlerPathDiscovery OidcHandlerPath = "/discovery"
	OidcHandlerPathJwks      OidcHandlerPath = "/jwks"
)
