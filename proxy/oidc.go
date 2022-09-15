package proxy

import (
	"github.com/corpix/gdk/crypto"
)

type (
	OidcHandlerPathName string
	OidcHandlerPath     string

	OidcParameterName string

	OidcToken         = OauthToken
	OidcTokenResponse struct {
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

	OidcParameterClientId         OidcParameterName = OidcParameterName(OauthParameterClientId)
	OidcParameterClientKey        OidcParameterName = OidcParameterName(OauthParameterClientKey)
	OidcParameterRedirectUri      OidcParameterName = OidcParameterName(OauthParameterRedirectUri)
	OidcParameterResponseType     OidcParameterName = OidcParameterName(OauthParameterResponseType)
	OidcParameterScope            OidcParameterName = OidcParameterName(OauthParameterScope)
	OidcParameterState            OidcParameterName = OidcParameterName(OauthParameterState)
	OidcParameterCode             OidcParameterName = OidcParameterName(OauthParameterCode)
	OidcParameterError            OidcParameterName = OidcParameterName(OauthParameterError)
	OidcParameterErrorDescription OidcParameterName = OidcParameterName(OauthParameterErrorDescription)
	OidcParameterGrantType        OidcParameterName = OidcParameterName(OauthParameterGrantType)

	OidcTokenMapKeyNickname OauthTokenMapKey = "nickname"
	OidcTokenMapKeyEmail    OauthTokenMapKey = "email"
	OidcTokenMapKeyGroups   OauthTokenMapKey = "groups"

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

	OidcTokenUserProfileMap = map[string]string{
		string(crypto.TokenHeaderMapKeySubject): UserProfileName,
		string(OidcTokenMapKeyNickname):         UserProfileName,
		string(OidcTokenMapKeyEmail):            UserProfileMail,
		string(OidcTokenMapKeyGroups):           UserProfileGroups,
	}
)
