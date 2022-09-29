package http

import (
	"math"
	"math/big"
	"time"

	"github.com/corpix/gdk/crypto"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/log"
	"github.com/corpix/gdk/template"
)

type (
	CsrfConfig struct {
		Enable   bool                `yaml:"enable"`
		Granular *bool               `yaml:"granular"`
		Methods  map[string]struct{} `yaml:"methods"`
		Key      string              `yaml:"key"`

		// FIXME: yaml parser insert instance even if this struct does not defined in yaml file
		*TokenConfig `yaml:",inline,omitempty"`
		*SkipConfig  `yaml:",inline,omitempty"`
	}
	Csrf                   = Token
	CsrfMapKey             = TokenMapKey
	CsrfTokenContainer     TokenContainer
	CsrfTokenEncodeDecoder TokenEncodeDecoder
	CsrfTokenValidator     TokenValidator
	CsrfTokenService       struct {
		Config        *CsrfConfig
		Container     CsrfTokenContainer
		EncodeDecoder CsrfTokenEncodeDecoder
		Validator     CsrfTokenValidator
	}
)

const (
	CsrfMapKeyPath  CsrfMapKey = "path"
	CsrfMapKeyNonce CsrfMapKey = "nonce"

	SessionMapKeyCsrfNonce SessionMapKey = "csrf-nonce"
)

func (c *CsrfConfig) Default() {
	if !c.Enable {
		return
	}

	if c.Granular == nil {
		v := true
		c.Granular = &v
	}
	if *c.Granular && len(c.Methods) == 0 {
		c.Methods = map[string]struct{}{
			MethodPost:   {},
			MethodPut:    {},
			MethodPatch:  {},
			MethodDelete: {},
		}
	}
	if c.Key == "" {
		c.Key = "_csrf"
	}

	//

	if c.TokenConfig == nil {
		c.TokenConfig = &TokenConfig{}
	}
	c.TokenConfig.Default()

	if c.SkipConfig == nil {
		c.SkipConfig = &SkipConfig{}
	}

	//

	if c.Validator == nil {
		c.Validator = &TokenValidatorConfig{}
	}
	c.Validator.Default()
	c.Validator.Expire = &crypto.TokenValidatorExpireConfig{}
	if c.Validator.Expire.MaxAge == nil {
		dur := 2 * time.Hour
		c.Validator.Expire.MaxAge = &dur
	}
	if c.Validator.Expire.TimeDrift == nil {
		dur := 30 * time.Second
		c.Validator.Expire.TimeDrift = &dur
	}
}

func (c *CsrfConfig) Validate() error {
	return nil
}

//

func CsrfTokenPathGet(t TokenMap) (string, error) {
	rawPath, ok := t.Get(CsrfMapKeyPath)
	if !ok {
		return "", errors.Errorf(
			"failed to load %q from csrf token payload",
			CsrfMapKeyPath,
		)
	}
	return rawPath.(string), nil
}

func CsrfTokenNonceGet(t TokenMap) (uint, error) {
	rawNonce, ok := t.Get(CsrfMapKeyNonce)
	if !ok {
		return 0, errors.Errorf(
			"failed to load %q from csrf token payload",
			CsrfMapKeyNonce,
		)
	}
	// NOTE: this is because different format parsers use different types
	// when unmarshaling numbers into interface{}
	switch nonce := rawNonce.(type) {
	case float64:
		return uint(nonce), nil
	case uint64:
		return uint(nonce), nil
	case uint:
		return nonce, nil
	case int:
		return uint(nonce), nil
	default:
		return 0, errors.Errorf("unknown csrf token nonce type %T for value %+v", rawNonce, rawNonce)
	}
}

func SessionTokenCsrfNonceGet(t TokenMap) uint {
	rawNonce, ok := t.Get(SessionMapKeyCsrfNonce)
	if !ok {
		sessionNonceBig, err := crypto.RandInt(big.NewInt(math.MaxInt))
		if err != nil {
			panic(err)
		}
		nonce := uint(sessionNonceBig.Uint64())
		SessionTokenCsrfNonceSet(t, nonce)
		return nonce
	}
	// NOTE: this is because different format parsers use different types
	// when unmarshaling numbers into interface{}
	switch nonce := rawNonce.(type) {
	case float64:
		return uint(nonce)
	case uint64:
		return uint(nonce)
	case uint:
		return nonce
	case int:
		return uint(nonce)
	default:
		panic(errors.Errorf("unknown session csrf token nonce type %T for value %+v", rawNonce, rawNonce))
	}
}

func SessionTokenCsrfNonceSet(t TokenMap, nonce uint) {
	t.Set(SessionMapKeyCsrfNonce, nonce)
}

//

func (srv *CsrfTokenService) SkipPaths(paths ...string) {
	for _, path := range paths {
		srv.Config.SkipPaths[path] = struct{}{}
	}
}

func (srv *CsrfTokenService) Generate(sess *Session, path string) ([]byte, error) {
	nonce := SessionTokenCsrfNonceGet(sess)

	csrf := NewCsrf(srv.Config)
	csrf.Payload[CsrfMapKeyPath] = path
	csrf.Payload[CsrfMapKeyNonce] = nonce

	tokenBytes, err := srv.Container.Encode(csrf)
	if err != nil {
		return nil, err
	}
	if srv.EncodeDecoder != nil {
		return srv.EncodeDecoder.Encode(tokenBytes)
	}
	return tokenBytes, nil
}

func (srv *CsrfTokenService) GenerateString(sess *Session, path string) (string, error) {
	t, err := srv.Generate(sess, path)
	if err != nil {
		return "", err
	}
	return string(t), nil
}

func (srv *CsrfTokenService) MustGenerate(sess *Session, path string) []byte {
	t, err := srv.Generate(sess, path)
	if err != nil {
		panic(err)
	}
	return t
}

func (srv *CsrfTokenService) MustGenerateString(sess *Session, path string) string {
	return string(srv.MustGenerate(sess, path))
}

func NewCsrfTokenService(c *CsrfConfig) *CsrfTokenService {
	return &CsrfTokenService{
		Config:        c,
		Container:     NewTokenContainer(c.Container),
		EncodeDecoder: NewTokenEncodeDecoder(c.Encoder),
		Validator:     NewTokenValidator(c.Validator),
	}
}

func (srv *CsrfTokenService) Validate(nonce uint, path string, token []byte) error {
	if !*srv.Config.Validator.Enable {
		return nil
	}

	if len(token) == 0 {
		return errors.New("csrf token should not be empty")
	}

	var (
		err error
		t   *Token
	)

	if srv.EncodeDecoder != nil {
		token, err = srv.EncodeDecoder.Decode(token)
		if err != nil {
			return log.NewEventDecoratorError(
				errors.Wrap(err, "failed to decode csrf token"),
				map[string]interface{}{
					"token-bytes": token,
				},
			)
		}
	}
	t, err = srv.Container.Decode(token)
	if err != nil {
		return log.NewEventDecoratorError(
			errors.Wrap(err, "failed to decode csrf token container"),
			map[string]interface{}{
				"token-bytes": token,
			},
		)
	}

	err = srv.Validator.Validate(t)
	if err != nil {
		return log.NewEventDecoratorError(
			errors.Wrap(err, "failed to validate token"),
			map[string]interface{}{
				"token": t,
			},
		)
	}

	//

	tokenNonce, err := CsrfTokenNonceGet(t)
	if err != nil {
		return log.NewEventDecoratorError(
			errors.Wrap(err, "failed to get nonce from csrf token"),
			map[string]interface{}{
				"token": t,
			},
		)
	}
	if tokenNonce != nonce {
		return log.NewEventDecoratorError(
			errors.New("csrf token nonce does not match the expected nonce"),
			map[string]interface{}{
				"token":          t,
				"token-nonce":    tokenNonce,
				"expected-nonce": nonce,
			},
		)
	}

	tokenPath, err := CsrfTokenPathGet(t)
	if err != nil {
		return log.NewEventDecoratorError(
			errors.Wrap(err, "failed to get path from csrf token"),
			map[string]interface{}{
				"token": t,
			},
		)
	}
	if tokenPath != path {
		return log.NewEventDecoratorError(
			errors.New("csrf token path does not match the expected path"),
			map[string]interface{}{
				"token":         t,
				"token-path":    tokenPath,
				"expected-path": path,
			},
		)
	}

	return nil
}

//

func NewCsrf(c *CsrfConfig) *Csrf {
	return NewToken(c.TokenConfig)
}

func MiddlewareCsrf(srv *CsrfTokenService) Middleware {
	granular := *srv.Config.Granular

	return func(h Handler) Handler {
		return HandlerFunc(func(w ResponseWriter, r *Request) {
			var (
				err          error
				l            log.Logger
				tokenBytes   []byte
				session      *Session
				sessionNonce uint
			)

			if Skip(srv.Config.SkipConfig, r) {
				goto next
			}
			if granular {
				if _, ok := srv.Config.Methods[r.Method]; !ok {
					goto next
				}
			}

			l = RequestLogGet(r)

			session = RequestSessionMustGet(r)
			sessionNonce = SessionTokenCsrfNonceGet(session)

			//

			tokenBytes = []byte(r.URL.Query().Get(srv.Config.Key))
			if len(tokenBytes) == 0 {
				err = r.ParseForm()
				if err != nil {
					l.Warn().Err(err).Msg("failed parse form to get csrf token")
					goto fail
				}
				tokenBytes = []byte(r.Form.Get(srv.Config.Key))
			}

			err = srv.Validate(sessionNonce, r.URL.Path, tokenBytes)
			if err != nil {
				log.Decorate(l.Warn().Err(err), err).
					Msg("csrf token validation failed")
				goto fail
			}
		next:
			h.ServeHTTP(w, r)
			return
		fail:
			w.WriteHeader(StatusBadRequest)
		})
	}
}

func WithCsrfTemplateFuncMap(g *CsrfTokenService) template.Option {
	return func(t *template.Template) {
		t.Funcs(template.FuncMap(map[string]interface{}{
			"csrf": g.MustGenerateString,
		}))
	}
}
