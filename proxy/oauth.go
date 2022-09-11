package proxy

import (
	"github.com/corpix/gdk/crypto"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/log"
)

type (
	OauthHandlerPathName string
	OauthHandlerPath     string

	OauthParameterName string

	OauthTokenConfig   = http.TokenConfig
	OauthTokenConfigs  = map[string]*OauthTokenConfig
	OauthToken         = http.Token
	OauthTokenResponse struct {
		Type         string `json:"token_type"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}
	OauthTokenPayloadKey    string
	OauthTokenType          string
	OauthTokenContainer     crypto.TokenContainer
	OauthTokenEncodeDecoder crypto.TokenEncodeDecoder
	OauthTokenValidator     crypto.TokenValidator
	OauthTokenTypeService   struct {
		Type          OauthTokenType
		Config        *OauthTokenConfig
		Container     OauthTokenContainer
		EncodeDecoder OauthTokenEncodeDecoder
		Validator     OauthTokenValidator
	}
	OauthTokenService map[OauthTokenType]*OauthTokenTypeService
)

const (
	OauthHandlerPathNameAuthorize OauthHandlerPathName = "authorize"
	OauthHandlerPathNameToken     OauthHandlerPathName = "token"
	OauthHandlerPathNameProfile   OauthHandlerPathName = "profile"
	OauthHandlerPathNameValidate  OauthHandlerPathName = "validate"

	OauthHandlerPathAuthorize OauthHandlerPath = "/authorize"
	OauthHandlerPathToken     OauthHandlerPath = "/token"
	OauthHandlerPathProfile   OauthHandlerPath = "/profile"
	OauthHandlerPathValidate  OauthHandlerPath = "/validate"

	//

	OauthParameterClientId         OauthParameterName = "client_id"
	OauthParameterClientKey        OauthParameterName = "client_secret"
	OauthParameterRedirectUri      OauthParameterName = "redirect_uri"
	OauthParameterResponseType     OauthParameterName = "response_type"
	OauthParameterScope            OauthParameterName = "scope"
	OauthParameterState            OauthParameterName = "state"
	OauthParameterCode             OauthParameterName = "code"
	OauthParameterError            OauthParameterName = "error"
	OauthParameterErrorDescription OauthParameterName = "error_description"
	OauthParameterGrantType        OauthParameterName = "grant_type"

	OauthTokenPayloadKeyType          OauthTokenPayloadKey = "type"
	OauthTokenPayloadKeyApplicationId OauthTokenPayloadKey = "application-id"
	OauthTokenPayloadKeySessionId     OauthTokenPayloadKey = "session-id"

	OauthTokenTypeCode    OauthTokenType = "code"
	OauthTokenTypeAccess  OauthTokenType = "access"
	OauthTokenTypeRefresh OauthTokenType = "refresh"
)

var (
	OauthHandlerPathNames = []OauthHandlerPathName{
		OauthHandlerPathNameAuthorize,
		OauthHandlerPathNameToken,
		OauthHandlerPathNameProfile,
		OauthHandlerPathNameValidate,
	}
	OauthHandlerPaths = map[OauthHandlerPathName]OauthHandlerPath{
		OauthHandlerPathNameAuthorize: OauthHandlerPathAuthorize,
		OauthHandlerPathNameToken:     OauthHandlerPathToken,
		OauthHandlerPathNameProfile:   OauthHandlerPathProfile,
		OauthHandlerPathNameValidate:  OauthHandlerPathValidate,
	}
)

//

func (srv OauthTokenService) New(typ OauthTokenType) *OauthToken {
	token := NewOauthToken(srv[typ].Config)
	token.Set(string(OauthTokenPayloadKeyType), typ)
	return token
}

func (srv OauthTokenService) Encode(typ OauthTokenType, token *OauthToken) ([]byte, error) {
	tokenBytes, err := srv[typ].Container.Encode(token)
	if err != nil {
		return nil, err
	}
	if srv[typ].EncodeDecoder != nil {
		return srv[typ].EncodeDecoder.Encode(tokenBytes)
	}
	return tokenBytes, nil
}

func (srv OauthTokenService) MustEncode(typ OauthTokenType, token *OauthToken) []byte {
	buf, err := srv.Encode(typ, token)
	if err != nil {
		panic(err)
	}
	return buf
}

func (srv OauthTokenService) Decode(typ OauthTokenType, buf []byte) (*OauthToken, error) {
	var err error
	if srv[typ].EncodeDecoder != nil {
		buf, err = srv[typ].EncodeDecoder.Decode(buf)
		if err != nil {
			return nil, err
		}
	}
	return srv[typ].Container.Decode(buf)
}

func (srv OauthTokenService) MustDecode(typ OauthTokenType, buf []byte) *OauthToken {
	t, err := srv.Decode(typ, buf)
	if err != nil {
		panic(err)
	}
	return t
}

func (srv OauthTokenService) Validate(typ OauthTokenType, t *OauthToken) error {
	if !*srv[typ].Config.Validator.Enable {
		return nil
	}

	err := srv[typ].Validator.Validate(t)
	if err != nil {
		return err
	}

	rawTyp, ok := t.Get(string(OauthTokenPayloadKeyType))
	if !ok {
		return log.NewEventDecoratorError(
			errors.New("token has no type in the payload"),
			map[string]interface{}{
				"expected-token-type": typ,
			},
		)
	}

	var currentTokenTyp OauthTokenType
	switch tokenTyp := rawTyp.(type) {
	case OauthTokenType:
		currentTokenTyp = tokenTyp
	case string:
		currentTokenTyp = OauthTokenType(tokenTyp)
	default:
		return log.NewEventDecoratorError(
			errors.Errorf("unsupported token type %T", rawTyp),
			map[string]interface{}{
				"token-type":          rawTyp,
				"expected-token-type": typ,
			},
		)
	}

	if currentTokenTyp != typ {
		return log.NewEventDecoratorError(
			errors.New("token type does not match expected"),
			map[string]interface{}{
				"token-type":          currentTokenTyp,
				"expected-token-type": typ,
			},
		)
	}

	return nil
}

func NewOauthTokenService(c OauthTokenConfigs) OauthTokenService {
	m := make(OauthTokenService, len(c))
	for k, v := range c {
		container := http.NewTokenContainer(v.Container)
		// TODO: maybe we could find a way to treat container a blackbox, not depending on the internal structure?
		// this could be achieved using options, but requires gdk api changes (crypto.NewTokenContainer)
		switch cont := container.(type) {
		case *crypto.TokenContainerJwt:
			cont.Key.Name = k

		}

		m[OauthTokenType(k)] = &OauthTokenTypeService{
			Type:          OauthTokenType(k),
			Config:        v,
			Container:     container,
			EncodeDecoder: crypto.NewTokenEncodeDecoder(v.Encoder),
			Validator:     crypto.NewTokenValidator(v.Validator),
		}
	}
	return m
}

//

func NewOauthToken(c *OauthTokenConfig) *OauthToken {
	return http.NewToken(c)
}
