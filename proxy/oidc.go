package proxy

type (
	OidcHandlerPathName string
	OidcHandlerPath     string
	OidcTokenType       string
)

const (
	OidcHandlerPathNameAuthorize OidcHandlerPathName = OidcHandlerPathName(OauthHandlerPathNameAuthorize)
	OidcHandlerPathNameToken     OidcHandlerPathName = OidcHandlerPathName(OauthHandlerPathNameToken)
	OidcHandlerPathNameProfile   OidcHandlerPathName = OidcHandlerPathName(OauthHandlerPathNameProfile)
	OidcHandlerPathNameValidate  OidcHandlerPathName = OidcHandlerPathName(OauthHandlerPathNameValidate)
	OidcHandlerPathNameDiscovery OidcHandlerPathName = "discovery"
	OidcHandlerPathNameJwks      OidcHandlerPathName = "jwks"

	OidcHandlerPathAuthorize OidcHandlerPath = OidcHandlerPath(OauthHandlerPathAuthorize)
	OidcHandlerPathToken     OidcHandlerPath = OidcHandlerPath(OauthHandlerPathToken)
	OidcHandlerPathProfile   OidcHandlerPath = OidcHandlerPath(OauthHandlerPathProfile)
	OidcHandlerPathValidate  OidcHandlerPath = OidcHandlerPath(OauthHandlerPathValidate)
	OidcHandlerPathDiscovery OidcHandlerPath = "/discovery"
	OidcHandlerPathJwks      OidcHandlerPath = "/jwks"

	OidcTokenTypeCode    OidcTokenType = OidcTokenType(OauthTokenTypeCode)
	OidcTokenTypeAccess  OidcTokenType = OidcTokenType(OauthTokenTypeAccess)
	OidcTokenTypeRefresh OidcTokenType = OidcTokenType(OauthTokenTypeRefresh)
	OidcTokenTypeId      OidcTokenType = "id_token"
)

var (
	OidcHandlerPathNames = []OidcHandlerPathName{
		// TODO: tokeinfo is required https://developers.google.com/identity/sign-in/web/backend-auth
		OidcHandlerPathNameAuthorize,
		OidcHandlerPathNameToken,
		OidcHandlerPathNameProfile,
		OidcHandlerPathNameValidate,
		OidcHandlerPathNameDiscovery,
		OidcHandlerPathNameJwks,
	}
	OidcHandlerPaths = map[OidcHandlerPathName]OidcHandlerPath{
		OidcHandlerPathNameAuthorize: OidcHandlerPathAuthorize,
		OidcHandlerPathNameToken:     OidcHandlerPathToken,
		OidcHandlerPathNameProfile:   OidcHandlerPathProfile,
		OidcHandlerPathNameValidate:  OidcHandlerPathValidate,
		OidcHandlerPathNameDiscovery: OidcHandlerPathDiscovery,
		OidcHandlerPathNameJwks:      OidcHandlerPathJwks,
	}
)
