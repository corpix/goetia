package proxy

import (
	"github.com/corpix/gdk/crypto"
)

type (
	OidcHandlerPathName string
	OidcHandlerPath     string
	OidcToken           = OauthToken
	OidcTokenResponse   struct {
		OauthTokenResponse `json:",inline"`
		IdToken            string `json:"id_token,omitempty"`
	}
	OidcTokenMapKey = crypto.TokenMapKey
	OidcTokenType   string
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

	OidcTokenMapKeyNickname OauthTokenMapKey = "nickname"
	OidcTokenMapKeyEmail    OauthTokenMapKey = "email"

	OidcTokenTypeCode    OidcTokenType = OidcTokenType(OauthTokenTypeCode)
	OidcTokenTypeAccess  OidcTokenType = OidcTokenType(OauthTokenTypeAccess)
	OidcTokenTypeRefresh OidcTokenType = OidcTokenType(OauthTokenTypeRefresh)
	OidcTokenTypeId      OidcTokenType = "id"
)

var (
	OidcHandlerPathNames = []OidcHandlerPathName{
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
