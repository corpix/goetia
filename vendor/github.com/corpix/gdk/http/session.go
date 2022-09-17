package http

import (
	"context"
	"time"

	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/log"
)

type (
	SessionConfig struct {
		Enable       bool           `yaml:"enable"`
		Refresh      *time.Duration `yaml:"refresh"`
		*TokenConfig `yaml:",inline,omitempty"`
		*SkipConfig  `yaml:",inline,omitempty"`
	}
	Session              = Token
	SessionStore         TokenStore
	SessionValidator     TokenValidator
	SessionEncodeDecoder TokenEncodeDecoder
	SessionContainer     TokenContainer
	SessionMapKey        = TokenMapKey
	SessionService       struct {
		Config        *SessionConfig
		Container     SessionContainer
		EncodeDecoder SessionEncodeDecoder
		Validator     SessionValidator
		Store         SessionStore
	}
)

func (c *SessionConfig) Default() {
	if !c.Enable {
		return
	}

	if c.TokenConfig == nil {
		c.TokenConfig = &TokenConfig{}
	}
	c.TokenConfig.Default()

	if c.Store == nil {
		c.Store = &TokenStoreConfig{}
	}
	if c.Store.Type == "" {
		c.Store.Type = string(TokenStoreTypeCookie)
	}

	if c.Validator == nil {
		c.Validator = &TokenValidatorConfig{}
	}
	c.Validator.Default()
	c.Validator.Expire.Default()
	if c.Validator.Expire.MaxAge == nil {
		dur := 24 * time.Hour
		c.Validator.Expire.MaxAge = &dur
	}
	if c.Validator.Expire.TimeDrift == nil {
		dur := 30 * time.Second
		c.Validator.Expire.TimeDrift = &dur
	}
	if c.Refresh == nil {
		dur := *c.Validator.Expire.MaxAge / 2
		c.Refresh = &dur
	}
	if c.SkipConfig == nil {
		c.SkipConfig = &SkipConfig{}
	}
}

func (c *SessionConfig) Validate() error {
	if !c.Enable {
		return nil
	}

	if *c.Refresh <= 0 {
		return errors.New("refresh should be larger than zero")
	}
	return nil
}

var (
	ContextKeySession = new(ContextKey)
)

//

func RequestSessionGet(c *SessionConfig, r *Request) *Session {
	ctxSession := r.Context().Value(ContextKeySession)
	if ctxSession != nil {
		return ctxSession.(*Session)
	}
	return NewToken(c.TokenConfig)
}

func RequestSessionMustGet(r *Request) *Session {
	ctxSession := r.Context().Value(ContextKeySession)
	if ctxSession != nil {
		return ctxSession.(*Session)
	}
	panic("no session in request context")
}

func RequestSessionSet(r *Request, s *Session) *Request {
	return r.WithContext(context.WithValue(r.Context(), ContextKeySession, s))
}

//

func (srv *SessionService) SkipPaths(paths ...string) {
	for _, path := range paths {
		srv.Config.SkipPaths[path] = struct{}{}
	}
}

func (srv *SessionService) Validate(t *Session) error {
	if !*srv.Config.Validator.Enable {
		return nil
	}

	err := srv.Validator.Validate(t)
	if err != nil {
		return log.NewEventDecoratorError(
			errors.New("failed to validate session"),
			map[string]interface{}{
				"session": t,
			},
		)
	}

	return nil
}

func (srv *SessionService) Expiring(t *Session) bool {
	return t.Header.ValidAfter.Add(*srv.Config.Refresh).Before(time.Now())
}

func (srv *SessionService) Refresh(t *Session) *Session {
	tc := srv.New()
	tc.Payload = t.Payload
	return tc
}

func (srv *SessionService) New() *Session {
	return NewSession(srv.Config)
}

func NewSessionService(c *SessionConfig) *SessionService {
	srv := &SessionService{
		Config:        c,
		Container:     NewTokenContainer(c.Container),
		EncodeDecoder: NewTokenEncodeDecoder(c.Encoder),
		Validator:     NewTokenValidator(c.Validator),
	}

	store, err := NewTokenStore(c.Store, srv.Container, srv.EncodeDecoder)
	if err != nil {
		panic(err)
	}

	srv.Store = store
	return srv
}

//

func MiddlewareSession(srv *SessionService) Middleware {
	return func(h Handler) Handler {
		return HandlerFunc(func(w ResponseWriter, r *Request) {
			if Skip(srv.Config.SkipConfig, r) {
				h.ServeHTTP(w, r)
				return
			}

			l := RequestLogGet(r)
			flush := false

			t, err := srv.Store.RequestLoad(r)
			if err != nil {
				t = srv.New()
				flush = true
				l.Warn().
					Interface("session", t).
					Err(err).
					Msg("failed to load session, created new")
			}

			err = srv.Validate(t)
			if err != nil {
				t = srv.New()
				flush = true
				log.Decorate(l.Warn().Err(err), err).
					Msg("invalid session, created new")
			}

			if srv.Expiring(t) {
				tc := srv.Refresh(t)
				t = tc
				flush = true
				l.Trace().
					Interface("expiring-session", t).
					Interface("session", tc).
					Msg("refreshed session")
			}

			r = RequestSessionSet(r, t)
			seqno := t.Seqno()

			h.ServeHTTP(w, r)

			if flush || t.Seqno() > seqno {
				_, err = srv.Store.RequestSave(w, r, t)
				if err != nil {
					l.Warn().
						Interface("session", t).
						Err(err).
						Msg("failed to save session")
					w.WriteHeader(StatusInternalServerError)
					return
				}
			}
		})
	}
}

func NewSession(c *SessionConfig) *Session {
	return NewToken(c.TokenConfig)
}
