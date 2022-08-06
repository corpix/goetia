package proxy

import (
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/log"
)

type (
	OauthHandlerPath   string
	OauthParameterName string

	OauthTokenConfig        = http.TokenConfig
	OauthToken              = http.Token
	OauthTokenPayloadKey    string
	OauthTokenType          string
	OauthTokenContainer     http.TokenContainer
	OauthTokenEncodeDecoder http.TokenEncodeDecoder
	OauthTokenValidator     http.TokenValidator
	OauthTokenService       struct {
		Config        *OauthTokenConfig
		Container     OauthTokenContainer
		EncodeDecoder OauthTokenEncodeDecoder
		Validator     OauthTokenValidator
	}
)

const (
	OauthHandlerPathAuthorize OauthHandlerPath = "/authorize"
	OauthHandlerPathToken     OauthHandlerPath = "/token"
	OauthHandlerPathProfile   OauthHandlerPath = "/profile"
	OauthHandlerPathValidate  OauthHandlerPath = "/validate"

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

//

func (srv *OauthTokenService) New(typ OauthTokenType) *OauthToken {
	token := NewOauthToken(srv.Config)
	token.Set(string(OauthTokenPayloadKeyType), typ)
	return token
}

func (srv *OauthTokenService) Encode(token *OauthToken) ([]byte, error) {
	tokenBytes, err := srv.Container.Encode(token)
	if err != nil {
		return nil, err
	}
	if srv.EncodeDecoder != nil {
		return srv.EncodeDecoder.Encode(tokenBytes)
	}
	return tokenBytes, nil
}

func (srv *OauthTokenService) MustEncode(token *OauthToken) []byte {
	buf, err := srv.Encode(token)
	if err != nil {
		panic(err)
	}
	return buf
}

func (srv *OauthTokenService) Decode(buf []byte) (*OauthToken, error) {
	var err error
	if srv.EncodeDecoder != nil {
		buf, err = srv.EncodeDecoder.Decode(buf)
		if err != nil {
			return nil, err
		}
	}
	return srv.Container.Decode(buf)
}

func (srv *OauthTokenService) MustDecode(buf []byte) *OauthToken {
	t, err := srv.Decode(buf)
	if err != nil {
		panic(err)
	}
	return t
}

func (srv *OauthTokenService) Validate(typ OauthTokenType, t *OauthToken) error {
	if !*srv.Config.Validator.Enable {
		return nil
	}

	err := srv.Validator.Validate(t)
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

func NewOauthTokenService(c *OauthTokenConfig) *OauthTokenService {
	return &OauthTokenService{
		Config:        c,
		Container:     http.NewTokenContainer(c.Container),
		EncodeDecoder: http.NewTokenEncodeDecoder(c.Encoder),
		Validator:     http.NewTokenValidator(c.Validator),
	}
}

//

func NewOauthToken(c *OauthTokenConfig) *OauthToken {
	return http.NewToken(c)
}
