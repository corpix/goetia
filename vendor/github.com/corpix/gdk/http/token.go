package http

import (
	"context"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/philippgille/gokv/redis"

	"github.com/corpix/gdk/crypto"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/kv"
)

type (
	Token                = crypto.Token
	TokenContainer       = crypto.TokenContainer
	TokenEncodeDecoder   = crypto.TokenEncodeDecoder
	TokenValidator       = crypto.TokenValidator
	TokenValidatorConfig = crypto.TokenValidatorConfig
	TokenMap             = crypto.TokenMap
	TokenPayload         = crypto.TokenPayload
	TokenMapKey          = crypto.TokenMapKey
	TokenContainerType   = crypto.TokenContainerType
	TokenValidatorType   = crypto.TokenValidatorType

	TokenConfig struct {
		Store               *TokenStoreConfig `yaml:"store,omitempty"`
		*crypto.TokenConfig `yaml:",inline"`
	}

	//

	TokenStoreConfig struct {
		Type   string                  `yaml:"type"`
		Cookie *TokenStoreCookieConfig `yaml:"cookie"`
		Redis  *TokenStoreRedisConfig  `yamnl:"redis"`
	}
	TokenStoreType string
	TokenStore     interface {
		Id(*Request) ([]byte, error)
		Save(*Token) ([]byte, error)
		RequestSave(ResponseWriter, *Request, *Token) ([]byte, error)
		Load([]byte) (*Token, error)
		RequestLoad(*Request) (*Token, error)
		Drop([]byte) error
		RequestDrop(ResponseWriter, *Request) error
	}

	TokenStoreCookieConfig struct {
		Name     string         `yaml:"name"`
		Path     string         `yaml:"path"`
		Domain   string         `yaml:"domain"`
		MaxAge   *time.Duration `yaml:"max-age,omitempty"`
		Secure   *bool          `yaml:"secure,omitempty"`
		HttpOnly *bool          `yaml:"httponly,omitempty"`
		SameSite string         `yaml:"same-site"`
	}
	TokenStoreCookie struct {
		Config        *TokenStoreCookieConfig
		Container     TokenContainer
		EncodeDecoder TokenEncodeDecoder
	}

	TokenStoreRedisConfig struct {
		Address      string                  `yaml:"address"`
		Password     string                  `yaml:"password"`
		PasswordFile string                  `yaml:"password-file"`
		Db           int                     `yaml:"db"`
		Cookie       *TokenStoreCookieConfig `yaml:"cookie"` // NOTE: we store id in cookie

		password string
	}
	TokenStoreRedis struct {
		Config        *TokenStoreRedisConfig
		Container     TokenContainer
		EncodeDecoder TokenEncodeDecoder
		Store         kv.Store
	}
)

const (
	TokenStoreTypeCookie TokenStoreType = "cookie"
	TokenStoreTypeRedis  TokenStoreType = "redis"
)

var (
	ContextKeyToken = new(ContextKey)

	_ TokenStore = new(TokenStoreCookie)
	_ TokenStore = new(TokenStoreRedis)

	NewTokenContainer     = crypto.NewTokenContainer
	NewTokenEncodeDecoder = crypto.NewTokenEncodeDecoder
	NewTokenValidator     = crypto.NewTokenValidator
)

func NewToken(c *TokenConfig) *Token {
	return crypto.NewToken(c.Unwrap())
}

//

func (c *TokenConfig) Default() {
	if c.TokenConfig == nil {
		c.TokenConfig = &crypto.TokenConfig{}
	}
	c.TokenConfig.Default()
}

func (c *TokenConfig) Unwrap() *crypto.TokenConfig {
	return c.TokenConfig
}

//

func RequestTokenGet(c *TokenConfig, r *Request) *Token {
	ctxToken := r.Context().Value(ContextKeyToken)
	if ctxToken != nil {
		return ctxToken.(*Token)
	}

	return crypto.NewToken(c.TokenConfig)
}

func RequestTokenSet(r *Request, s *Token) *Request {
	return r.WithContext(context.WithValue(r.Context(), ContextKeyToken, s))
}

//

func (c *TokenStoreConfig) Default() {
	if c.Type == string(TokenStoreTypeCookie) && c.Cookie == nil {
		c.Cookie = &TokenStoreCookieConfig{}
	}
	if c.Type == string(TokenStoreTypeRedis) && c.Redis == nil {
		c.Redis = &TokenStoreRedisConfig{}
	}
}

func (c *TokenStoreCookieConfig) Default() {
	if c.Name == "" {
		c.Name = fmt.Sprintf(
			"_%s",
			crypto.Sha1("gdk token cookie")[:8],
		)
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if c.Secure == nil {
		b := false
		c.Secure = &b
	}
	if c.HttpOnly == nil {
		b := true
		c.HttpOnly = &b
	}
	if c.SameSite == "" {
		c.SameSite = CookieSameSiteModesString[CookieSameSiteDefaultMode]
	}
}

func (c *TokenStoreCookieConfig) Validate() error {
	if _, ok := CookieSameSiteModes[c.SameSite]; !ok {
		available := make([]string, len(CookieSameSiteModes))
		n := 0
		for k := range CookieSameSiteModes {
			available[n] = k
			n++
		}
		sort.Strings(available)

		return errors.Errorf(
			"unexpected same-site value %q, expected one of: %q",
			c.SameSite, available,
		)
	}

	return nil
}

func (c *TokenStoreCookieConfig) Cookie() *Cookie {
	cookie := &Cookie{
		Name:     c.Name,
		Path:     c.Path,
		Domain:   c.Domain,
		Secure:   *c.Secure,
		HttpOnly: *c.HttpOnly,
		SameSite: CookieSameSiteModes[strings.ToLower(c.SameSite)],
	}
	if c.MaxAge != nil {
		cookie.MaxAge = int(*c.MaxAge / time.Second)
		cookie.Expires = time.Now().Add(*c.MaxAge)
	}
	return cookie
}

func (s *TokenStoreCookie) Id(r *Request) ([]byte, error) {
	cookie, err := CookieGet(r, s.Config.Name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get cookie from request")
	}
	return []byte(cookie.Value), nil
}

func (s *TokenStoreCookie) Save(t *Token) ([]byte, error) {
	id, err := s.Container.Encode(t)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode container")
	}

	if s.EncodeDecoder != nil {
		id, err = s.EncodeDecoder.Encode(id)
		if err != nil {
			return nil, errors.Wrap(err, "failed to encode cookie value")
		}
	}
	return id, nil
}

func (s *TokenStoreCookie) RequestSave(w ResponseWriter, r *Request, t *Token) ([]byte, error) {
	id, err := s.Save(t)
	if err != nil {
		return nil, err
	}

	cookie := s.Config.Cookie()
	cookie.Value = string(id)
	CookieSet(w, cookie)
	return id, nil
}

func (s *TokenStoreCookie) Load(id []byte) (*Token, error) {
	var err error
	if s.EncodeDecoder != nil {
		id, err = s.EncodeDecoder.Decode(id)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode cookie value")
		}
	}

	t, err := s.Container.Decode(id)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode container")
	}
	return t, nil
}

func (s *TokenStoreCookie) RequestLoad(r *Request) (*Token, error) {
	id, err := s.Id(r)
	if err != nil {
		return nil, err
	}
	t, err := s.Load(id)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *TokenStoreCookie) Drop(id []byte) error {
	// NOTE: nothing to do, buf is the session itself, we should only drop the cookie
	// which is handled by RequestDrop(...)
	return nil
}

func (s *TokenStoreCookie) RequestDrop(w ResponseWriter, r *Request) error {
	cookie := s.Config.Cookie()
	cookie.Expires = time.Time{} // 0001-01-01 00:00:00 +0000 UTC

	CookieSet(w, cookie)
	return nil
}

func NewTokenStoreCookie(c *TokenStoreCookieConfig, cont TokenContainer, enc TokenEncodeDecoder) *TokenStoreCookie {
	return &TokenStoreCookie{
		Config:        c,
		Container:     cont,
		EncodeDecoder: enc,
	}
}

//

func (c *TokenStoreRedisConfig) Default() {
	if c.Address == "" {
		c.Address = "127.0.0.1:6379"
	}
	if c.Cookie == nil {
		c.Cookie = &TokenStoreCookieConfig{}
	}
}

func (c *TokenStoreRedisConfig) Validate() error {
	if c.Password != "" && c.PasswordFile != "" {
		return errors.New("either password or password-file should be specified, not both")
	}

	return nil
}

func (c *TokenStoreRedisConfig) Expand() error {
	if c.PasswordFile != "" {
		passwordBytes, err := ioutil.ReadFile(c.PasswordFile)
		if err != nil {
			return err
		}
		c.password = string(passwordBytes)
	} else {
		c.password = c.Password
	}
	return nil
}

func (s *TokenStoreRedis) Id(r *Request) ([]byte, error) {
	cookie, err := CookieGet(r, s.Config.Cookie.Name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get cookie from request")
	}
	return []byte(cookie.Value), nil
}

func (s *TokenStoreRedis) Save(t *Token) ([]byte, error) {
	var id string
	rawId, ok := t.Get(crypto.TokenHeaderMapKeyId)
	if ok {
		id = rawId.(string)
	} else {
		id = uuid.NewString()
		t.Set(crypto.TokenHeaderMapKeyId, id)
	}

	buf, err := s.Container.Encode(t)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode token container")
	}
	if s.EncodeDecoder != nil {
		buf, err = s.EncodeDecoder.Encode(buf)
		if err != nil {
			return nil, errors.Wrap(err, "failed to encode token value")
		}
	}

	err = s.Store.Set(id, buf)
	if err != nil {
		return nil, err
	}

	return []byte(id), nil
}

func (s *TokenStoreRedis) RequestSave(w ResponseWriter, r *Request, t *Token) ([]byte, error) {
	id, err := s.Save(t)
	if err != nil {
		return nil, err
	}

	cookie := s.Config.Cookie.Cookie()
	cookie.Value = string(id)
	CookieSet(w, cookie)

	return id, nil
}

func (s *TokenStoreRedis) Load(id []byte) (*Token, error) {
	var (
		buf []byte
		err error
	)

	ok, err := s.Store.Get(string(id), &buf)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.Errorf("no key with id %q", string(id))
	}

	if s.EncodeDecoder != nil {
		buf, err = s.EncodeDecoder.Decode(buf)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode token value")
		}
	}
	t, err := s.Container.Decode(buf)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode token container")
	}

	return t, nil
}

func (s *TokenStoreRedis) RequestLoad(r *Request) (*Token, error) {
	id, err := s.Id(r)
	if err != nil {
		return nil, err
	}
	t, err := s.Load(id)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *TokenStoreRedis) Drop(id []byte) error {
	return s.Store.Delete(string(id))
}

func (s *TokenStoreRedis) RequestDrop(w ResponseWriter, r *Request) error {
	id, err := s.Id(r)
	if err != nil {
		return err
	}

	cookie := s.Config.Cookie.Cookie()
	cookie.MaxAge = 0
	cookie.Expires = time.Time{} // 0001-01-01 00:00:00 +0000 UTC
	CookieSet(w, cookie)

	return s.Drop(id)
}

func NewTokenStoreRedis(c *TokenStoreRedisConfig, cont TokenContainer, enc TokenEncodeDecoder) *TokenStoreRedis {
	options := redis.Options{
		Address:  c.Address,
		Password: c.password,
		DB:       c.Db,
	}
	s, err := redis.NewClient(options)
	if err != nil {
		panic(err)
	}

	return &TokenStoreRedis{
		Config:        c,
		Container:     cont,
		EncodeDecoder: enc,
		Store:         s,
	}
}

//

func NewTokenStore(c *TokenStoreConfig, cont TokenContainer, enc TokenEncodeDecoder) (TokenStore, error) {
	switch strings.ToLower(c.Type) {
	case string(TokenStoreTypeCookie):
		return NewTokenStoreCookie(c.Cookie, cont, enc), nil
	case string(TokenStoreTypeRedis):
		return NewTokenStoreRedis(c.Redis, cont, enc), nil
	default:
		return nil, errors.Errorf("unsupported store type: %q", c.Type)
	}
}
