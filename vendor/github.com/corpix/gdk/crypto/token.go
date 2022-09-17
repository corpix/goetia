package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"strings"
	"time"

	jwt "github.com/cristalhq/jwt/v4"
	msgpack "github.com/vmihailenco/msgpack/v5"

	"github.com/corpix/gdk/encoding"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/reflect"
)

type (
	TokenConfig struct {
		Container *TokenContainerConfig `yaml:"container"`
		Encoder   string                `yaml:"encoder"`
		Validator *TokenValidatorConfig `yaml:"validator"`
	}
	Token struct {
		seqno   uint
		Header  TokenHeader  `json:"header"`
		Payload TokenPayload `json:"payload"`
	}
	TokenCap    uint8
	TokenHeader struct {
		ValidAfter  time.Time    `json:"valid-after"`
		ValidBefore time.Time    `json:"valid-before"`
		Meta        TokenPayload `json:"meta,omitempty"`
	}
	TokenPayload map[TokenMapKey]interface{}
	TokenMapKey  string
	TokenMap     interface {
		Get(key TokenMapKey) (interface{}, bool)
		Set(key TokenMapKey, value interface{})
		Del(key TokenMapKey) bool
	}

	TokenJwt          map[TokenMapKey]interface{}
	TokenJwtAlgorithm = jwt.Algorithm
	TokenJwtHeader    = jwt.Header

	// see https://www.rfc-editor.org/rfc/rfc7517#page-5
	TokenJwtKey struct {
		Name       string            `json:"kid,omitempty"`
		Type       TokenJwtKeyType   `json:"kty"`
		Use        string            `json:"use,omitempty"`
		Operations []string          `json:"key_ops,omitempty"`
		Algorithm  TokenJwtAlgorithm `json:"alg,omitempty"`

		// RSA
		Exponent string `json:"e,omitempty"`
		Modulus  string `json:"n,omitempty"`

		// EC
		Curve    string `json:"crv,omitempty"`
		Abscissa string `json:"x,omitempty"`
		Ordinate string `json:"y,omitempty"`
	}
	TokenJwtKeyType string
	TokenJwtKeySet  struct {
		Keys []*TokenJwtKey `json:"keys"`
	}

	//

	TokenContainerConfig struct {
		Type      string                         `yaml:"type"`
		Json      *TokenContainerJsonConfig      `yaml:"json,omitempty"`
		Jwt       *TokenContainerJwtConfig       `yaml:"jwt,omitempty"`
		Msgpack   *TokenContainerMsgpackConfig   `yaml:"msgpack,omitempty"`
		SecretBox *TokenContainerSecretBoxConfig `yaml:"secretbox,omitempty"`
	}
	TokenContainerType       string
	TokenContainerJsonConfig struct{}
	TokenContainerJwtConfig  struct {
		Algorithm string `yaml:"algorithm"`

		Key     string `yaml:"key,omitempty"`
		KeyFile string `yaml:"key-file,omitempty"`
		key     []byte
	}
	TokenContainerMsgpackConfig   struct{}
	TokenContainerSecretBoxConfig struct {
		Key       string `yaml:"key,omitempty"`
		KeyFile   string `yaml:"key-file,omitempty"`
		key       SecretBoxKey
		Container *TokenContainerConfig `yaml:"container"`
	}

	TokenContainer interface {
		Encode(*Token) ([]byte, error)
		Decode([]byte) (*Token, error)
		Cap() TokenCap
	}
	TokenContainerJson struct {
		Config *TokenContainerJsonConfig
	}
	TokenContainerJwt struct {
		Config   *TokenContainerJwtConfig
		Builder  *jwt.Builder
		Verifier jwt.Verifier
		Key      *TokenJwtKey
	}
	TokenContainerMsgpack struct {
		Config *TokenContainerMsgpackConfig
	}
	TokenContainerSecretBox struct {
		Config    *TokenContainerSecretBoxConfig
		Container TokenContainer
		SecretBox *SecretBox
	}

	TokenEncodeDecoderType string
	TokenEncodeDecoder     encoding.EncodeDecoder

	TokenValidatorConfig struct {
		Enable *bool                       `yaml:"enable"`
		Type   string                      `yaml:"type"`
		Expire *TokenValidatorExpireConfig `yaml:"expire"`
	}
	TokenValidatorExpireConfig struct {
		MaxAge    *time.Duration `yaml:"max-age"`
		TimeDrift *time.Duration `yaml:"time-drift"`
	}
	TokenValidatorType string
	TokenValidator     interface {
		Validate(*Token) error
	}
	TokenValidatorExpire struct {
		Config *TokenValidatorExpireConfig
	}

	TokenService struct {
		Config        *TokenConfig
		Options       []TokenServiceOption
		Container     TokenContainer
		EncodeDecoder TokenEncodeDecoder
		Validator     TokenValidator
	}
	TokenServiceOption func(*Token)
)

const (
	TokenCapAuthenticated TokenCap = 1 << iota
	TokenCapEncrypted
	TokenCapSharedSecret
	TokenCapPubKeyCrypto
)

const (
	TokenHeaderMapKeyId       TokenMapKey = "id"
	TokenHeaderMapKeyAudience TokenMapKey = "audience"
	TokenHeaderMapKeyIssuer   TokenMapKey = "issuer"
	TokenHeaderMapKeySubject  TokenMapKey = "subject"

	TokenJwtMapKeyId        TokenMapKey = "jti"
	TokenJwtMapKeyAudience  TokenMapKey = "aud"
	TokenJwtMapKeyIssuer    TokenMapKey = "iss"
	TokenJwtMapKeySubject   TokenMapKey = "sub"
	TokenJwtMapKeyExpiresAt TokenMapKey = "exp"
	TokenJwtMapKeyIssuedAt  TokenMapKey = "iat"
	TokenJwtMapKeyNotBefore TokenMapKey = "nbf"
	TokenJwtMapKeyPayload   TokenMapKey = "payload"

	TokenEncodeDecoderTypeRaw    TokenEncodeDecoderType = "raw"
	TokenEncodeDecoderTypeBase64 TokenEncodeDecoderType = "base64"

	TokenContainerTypeJson      TokenContainerType = "json"
	TokenContainerTypeJwt       TokenContainerType = "jwt"
	TokenContainerTypeMsgpack   TokenContainerType = "msgpack"
	TokenContainerTypeSecretBox TokenContainerType = "secretbox"

	TokenJwtKeyTypeRSA TokenJwtKeyType = "RSA"
	TokenJwtKeyTypeEC  TokenJwtKeyType = "EC"

	TokenJwtAlgorithmEdDSA TokenJwtAlgorithm = jwt.EdDSA
	TokenJwtAlgorithmHS256 TokenJwtAlgorithm = jwt.HS256
	TokenJwtAlgorithmHS384 TokenJwtAlgorithm = jwt.HS384
	TokenJwtAlgorithmHS512 TokenJwtAlgorithm = jwt.HS512
	TokenJwtAlgorithmRS256 TokenJwtAlgorithm = jwt.RS256
	TokenJwtAlgorithmRS384 TokenJwtAlgorithm = jwt.RS384
	TokenJwtAlgorithmRS512 TokenJwtAlgorithm = jwt.RS512
	TokenJwtAlgorithmES256 TokenJwtAlgorithm = jwt.ES256
	TokenJwtAlgorithmES384 TokenJwtAlgorithm = jwt.ES384
	TokenJwtAlgorithmES512 TokenJwtAlgorithm = jwt.ES512
	TokenJwtAlgorithmPS256 TokenJwtAlgorithm = jwt.PS256
	TokenJwtAlgorithmPS384 TokenJwtAlgorithm = jwt.PS384
	TokenJwtAlgorithmPS512 TokenJwtAlgorithm = jwt.PS512

	TokenValidatorTypeExpire TokenValidatorType = "expire"
)

var (
	TokenJwtHeaderMapKeys = map[TokenMapKey]TokenMapKey{
		TokenHeaderMapKeyId:       TokenJwtMapKeyId,
		TokenHeaderMapKeyAudience: TokenJwtMapKeyAudience,
		TokenHeaderMapKeyIssuer:   TokenJwtMapKeyIssuer,
		TokenHeaderMapKeySubject:  TokenJwtMapKeySubject,
	}

	TokenJwtAlgorithms = map[string]TokenJwtAlgorithm{
		strings.ToLower(string(TokenJwtAlgorithmEdDSA)): TokenJwtAlgorithmEdDSA,
		strings.ToLower(string(TokenJwtAlgorithmHS256)): TokenJwtAlgorithmHS256,
		strings.ToLower(string(TokenJwtAlgorithmHS384)): TokenJwtAlgorithmHS384,
		strings.ToLower(string(TokenJwtAlgorithmHS512)): TokenJwtAlgorithmHS512,
		strings.ToLower(string(TokenJwtAlgorithmRS256)): TokenJwtAlgorithmRS256,
		strings.ToLower(string(TokenJwtAlgorithmRS384)): TokenJwtAlgorithmRS384,
		strings.ToLower(string(TokenJwtAlgorithmRS512)): TokenJwtAlgorithmRS512,
		strings.ToLower(string(TokenJwtAlgorithmES256)): TokenJwtAlgorithmES256,
		strings.ToLower(string(TokenJwtAlgorithmES384)): TokenJwtAlgorithmES384,
		strings.ToLower(string(TokenJwtAlgorithmES512)): TokenJwtAlgorithmES512,
		strings.ToLower(string(TokenJwtAlgorithmPS256)): TokenJwtAlgorithmPS256,
		strings.ToLower(string(TokenJwtAlgorithmPS384)): TokenJwtAlgorithmPS384,
		strings.ToLower(string(TokenJwtAlgorithmPS512)): TokenJwtAlgorithmPS512,
	}

	TokenJwtErrInvalidFormat     = jwt.ErrInvalidFormat
	TokenJwtErrAlgorithmMismatch = jwt.ErrAlgorithmMismatch
	TokenJwtErrInvalidSignature  = jwt.ErrInvalidSignature

	_ TokenContainer = new(TokenContainerJson)
	_ TokenContainer = new(TokenContainerJwt)
	_ TokenContainer = new(TokenContainerMsgpack)
	_ TokenContainer = new(TokenContainerSecretBox)

	_ TokenValidator = new(TokenValidatorExpire)
)

//

func (c *TokenConfig) Default() {
	if c.Container == nil {
		c.Container = &TokenContainerConfig{}
	}
	if c.Encoder == "" {
		c.Encoder = string(TokenEncodeDecoderTypeRaw)
	}
	if c.Validator == nil {
		c.Validator = &TokenValidatorConfig{}
	}
}

func (c *TokenConfig) Validate() error {
	switch TokenEncodeDecoderType(strings.ToLower(c.Encoder)) {
	case
		TokenEncodeDecoderTypeRaw,
		TokenEncodeDecoderTypeBase64:
	default:
		return errors.Errorf("unsupported encode decoder %q", c.Encoder)
	}
	return nil
}

//

func (b TokenCap) Set(flag TokenCap) TokenCap    { return b | flag }
func (b TokenCap) Clear(flag TokenCap) TokenCap  { return b &^ flag }
func (b TokenCap) Toggle(flag TokenCap) TokenCap { return b ^ flag }
func (b TokenCap) Has(flag TokenCap) bool        { return b&flag != 0 }

func NewTokenCap(flag ...TokenCap) TokenCap {
	var b TokenCap
	for _, f := range flag {
		b = b.Set(f)
	}
	return b
}

//

func (c *TokenContainerConfig) Default() {
	if c.Type == "" {
		c.Type = string(TokenContainerTypeSecretBox)
	}

	if c.Type == string(TokenContainerTypeJson) && c.Json == nil {
		c.Json = &TokenContainerJsonConfig{}
	}
	if c.Type == string(TokenContainerTypeJwt) && c.Jwt == nil {
		c.Jwt = &TokenContainerJwtConfig{}
	}
	if c.Type == string(TokenContainerTypeMsgpack) && c.Msgpack == nil {
		c.Msgpack = &TokenContainerMsgpackConfig{}
	}
	if c.Type == string(TokenContainerTypeSecretBox) && c.SecretBox == nil {
		c.SecretBox = &TokenContainerSecretBoxConfig{}
	}
}

func (c *TokenContainerConfig) Validate() error {
	switch TokenContainerType(strings.ToLower(c.Type)) {
	case
		TokenContainerTypeJson,
		TokenContainerTypeJwt,
		TokenContainerTypeMsgpack,
		TokenContainerTypeSecretBox:
	default:
		return errors.Errorf("unsupported container type %q", c.Type)
	}
	return nil
}

//

func (c *TokenValidatorConfig) Default() {
	if c.Enable == nil {
		v := true
		c.Enable = &v
	}
	if c.Type == "" {
		c.Type = string(TokenValidatorTypeExpire)
	}
	// NOTE: Expirity is a mandatory behavior of the token
	// So, configuration should persist
	// Because we will calculate validBefore field based on this values
	if c.Expire == nil {
		c.Expire = &TokenValidatorExpireConfig{}
	}
}

func (c *TokenValidatorConfig) Validate() error {
	switch TokenValidatorType(strings.ToLower(c.Type)) {
	case
		TokenValidatorTypeExpire:
	default:
		return errors.Errorf("unsupported validator type %q", c.Type)
	}
	return nil
}

func (c *TokenValidatorExpireConfig) Default() {
	if c.MaxAge == nil {
		dur := 24 * time.Hour
		c.MaxAge = &dur
	}
	if c.TimeDrift == nil {
		dur := 30 * time.Second
		c.TimeDrift = &dur
	}
}

func (c *TokenValidatorExpireConfig) Validate() error {
	if *c.MaxAge <= 0 {
		return errors.New("max-age should be larger than zero")
	}
	if *c.TimeDrift < 0 {
		return errors.New("time-drift should be positive")
	}
	return nil
}

func (v *TokenValidatorExpire) Validate(t *Token) error {
	now := time.Now()

	if now.Before(t.Header.ValidAfter) {
		switch { // TODO: log clock skew? should have some sort of time based flag to prevent log flooding (log every 10 minutes or something)
		case now.Add(*v.Config.TimeDrift).After(t.Header.ValidAfter):
		default:
			return errors.Errorf(
				"token validity period has not started yet, valid after %q, but current time %q",
				t.Header.ValidAfter,
				now,
			)
		}
	}

	if now.After(t.Header.ValidBefore) {
		switch { // TODO: log clock skew? should have some sort of time based flag to prevent log flooding (log every 10 minutes or something)
		case now.Add(-*v.Config.TimeDrift).Before(t.Header.ValidBefore):
		default:
			return errors.Errorf(
				"token expired, valid before %q, but current time %q",
				t.Header.ValidBefore,
				now,
			)
		}
	}

	return nil
}

func NewTokenValidator(c *TokenValidatorConfig) TokenValidator {
	switch TokenValidatorType(strings.ToLower(c.Type)) {
	case TokenValidatorTypeExpire:
		return NewTokenValidatorExpire(c.Expire)
	default:
		panic(errors.Errorf("unsupported validator type %q", c.Type))
	}
}

func NewTokenValidatorExpire(c *TokenValidatorExpireConfig) *TokenValidatorExpire {
	return &TokenValidatorExpire{
		Config: c,
	}
}

//

func (c *TokenContainerJwtConfig) Validate() error {
	if c.Key != "" && c.KeyFile != "" {
		return errors.New("either key or key-file must be defined, not both")
	}
	if c.Key == "" && c.KeyFile == "" {
		return errors.New("either key or key-file must be defined")
	}
	if len(c.key) == 0 {
		return errors.New("key length should be greater than zero")
	}
	return nil
}

func (c *TokenContainerJwtConfig) Expand() error {
	var err error
	if c.KeyFile != "" {
		c.key, err = ioutil.ReadFile(c.KeyFile)
		if err != nil {
			return errors.Wrapf(err, "failed to load key-file: %q", c.KeyFile)
		}
	} else {
		c.key = []byte(c.Key)
	}
	return nil
}

//

func (c *TokenContainerSecretBoxConfig) Default() {
	if c.Container == nil {
		c.Container = &TokenContainerConfig{}
	}
	if c.Container.Type == "" {
		c.Container.Type = string(TokenContainerTypeMsgpack)
	}
}

func (c *TokenContainerSecretBoxConfig) Validate() error {
	if c.Key != "" && c.KeyFile != "" {
		return errors.New("either key or key-file must be defined, not both")
	}
	if c.Key == "" && c.KeyFile == "" {
		return errors.New("either key or key-file must be defined")
	}

	var emptyKey SecretBoxKey
	if bytes.Equal(c.key[:], emptyKey[:]) {
		return errors.Errorf("key be %d non-zero bytes", SecretBoxKeySize)
	}
	return nil
}

func (c *TokenContainerSecretBoxConfig) Expand() error {
	var (
		err error
		key []byte
	)
	if c.KeyFile != "" {
		key, err = ioutil.ReadFile(c.KeyFile)
		if err != nil {
			return errors.Wrapf(err, "failed to load key-file: %q", c.KeyFile)
		}
	} else {
		key = []byte(c.Key)
	}
	copy(c.key[:], key)
	return nil
}

//

func (t *Token) Get(key TokenMapKey) (interface{}, bool)  { return t.Payload.Get(key) }
func (t *Token) MustGet(key TokenMapKey) interface{}      { return t.Payload.MustGet(key) }
func (t *Token) GetBool(key TokenMapKey) (bool, bool)     { return t.Payload.GetBool(key) }
func (t *Token) MustGetBool(key TokenMapKey) bool         { return t.Payload.MustGetBool(key) }
func (t *Token) GetInt(key TokenMapKey) (int, bool)       { return t.Payload.GetInt(key) }
func (t *Token) MustGetInt(key TokenMapKey) int           { return t.Payload.MustGetInt(key) }
func (t *Token) GetUint(key TokenMapKey) (uint, bool)     { return t.Payload.GetUint(key) }
func (t *Token) MustGetUint(key TokenMapKey) uint         { return t.Payload.MustGetUint(key) }
func (t *Token) GetString(key TokenMapKey) (string, bool) { return t.Payload.GetString(key) }
func (t *Token) MustGetString(key TokenMapKey) string     { return t.Payload.MustGetString(key) }
func (t *Token) GetStringSlice(key TokenMapKey) ([]string, bool) {
	return t.Payload.GetStringSlice(key)
}
func (t *Token) MustGetStringSlice(key TokenMapKey) []string {
	return t.Payload.MustGetStringSlice(key)
}

func (t *Token) Seqno() uint { return t.seqno }
func (t *Token) Set(key TokenMapKey, value interface{}) {
	t.Payload.Set(key, value)
	t.seqno++
}
func (t *Token) Del(key TokenMapKey) bool {
	if t.Payload.Del(key) {
		t.seqno++
		return true
	}
	return false
}

//

func (p TokenPayload) Get(key TokenMapKey) (interface{}, bool) {
	v, ok := p[key]
	return v, ok
}

func (p TokenPayload) MustGet(key TokenMapKey) interface{} {
	v, ok := p.Get(key)
	if !ok {
		panic(errors.Errorf("no key %q found", key))
	}
	return v
}

func (p TokenPayload) GetBool(key TokenMapKey) (bool, bool) {
	v, ok := p[key]
	if ok {
		return v.(bool), ok
	}
	return false, false
}

func (p TokenPayload) MustGetBool(key TokenMapKey) bool {
	return p.MustGet(key).(bool)
}

func (p TokenPayload) GetInt(key TokenMapKey) (int, bool) {
	v, ok := p[key]
	if ok {
		return v.(int), ok
	}
	return 0, false
}

func (p TokenPayload) MustGetInt(key TokenMapKey) int {
	return p.MustGet(key).(int)
}

func (p TokenPayload) GetUint(key TokenMapKey) (uint, bool) {
	v, ok := p[key]
	if ok {
		return v.(uint), ok
	}
	return 0, false
}

func (p TokenPayload) MustGetUint(key TokenMapKey) uint {
	return p.MustGet(key).(uint)
}

func (p TokenPayload) GetString(key TokenMapKey) (string, bool) {
	v, ok := p[key]
	if ok {
		return v.(string), ok
	}
	return "", false
}

func (p TokenPayload) MustGetString(key TokenMapKey) string {
	return p.MustGet(key).(string)
}

func (p TokenPayload) GetStringSlice(key TokenMapKey) ([]string, bool) {
	v, ok := p[key]
	if ok {
		return v.([]string), ok
	}
	return []string{}, false
}

func (p TokenPayload) MustGetStringSlice(key TokenMapKey) []string {
	return p.MustGet(key).([]string)
}

func (p TokenPayload) Set(key TokenMapKey, value interface{}) {
	p[key] = value
}

func (p TokenPayload) Del(key TokenMapKey) bool {
	_, ok := p[key]
	if ok {
		delete(p, key)
		return true
	}
	return false
}

//

func NewToken(c *TokenConfig) *Token {
	now := time.Now()
	return &Token{
		seqno: 0,
		Header: TokenHeader{
			ValidAfter:  now,
			ValidBefore: now.Add(*c.Validator.Expire.MaxAge),
			Meta:        TokenPayload{},
		},
		Payload: TokenPayload{},
	}
}

//

// JWK RFC requires lexicographical ordering of keys on JSON
// so stable checksums could be calculated
// https://www.rfc-editor.org/rfc/rfc7638#section-3.3
// we utilize the thing in encoding/json which marshals map's
// keys in lexicographical order
// (structs fields marshaled in order declared in it's type)
func (k *TokenJwtKey) MarshalJSON() ([]byte, error) {
	rv := reflect.IndirectValue(reflect.ValueOf(k))
	rt := rv.Type()
	m := map[string]interface{}{}

loop:
	for n := 0; n < rt.NumField(); n++ {
		tag := strings.Split(rt.Field(n).Tag.Get("json"), ",")
		name := tag[0]
		value := rv.Field(n).Interface()
		if len(tag) > 1 && tag[1] == "omitempty" {
			switch v := value.(type) {
			case string:
				if len(v) == 0 {
					continue loop
				}
			case []string:
				if len(v) == 0 {
					continue loop
				}
			}
		}
		m[name] = value
	}
	return json.Marshal(m)
}

func NewTokenJwtKey(pub PublicKey) *TokenJwtKey {
	// see https://tools.ietf.org/html/rfc7518#section-6.2.1
	// see https://tools.ietf.org/html/rfc7518#section-6.3.1
	// see https://tools.ietf.org/html/rfc7638#section-3.3
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		p := pub.Curve.Params()
		n := p.BitSize / 8
		if p.BitSize%8 != 0 {
			n++
		}
		x := pub.X.Bytes()
		if n > len(x) {
			x = append(make([]byte, n-len(x)), x...)
		}
		y := pub.Y.Bytes()
		if n > len(y) {
			y = append(make([]byte, n-len(y)), y...)
		}
		return &TokenJwtKey{
			Type:     TokenJwtKeyTypeEC,
			Curve:    p.Name,
			Abscissa: base64.RawURLEncoding.EncodeToString(x),
			Ordinate: base64.RawURLEncoding.EncodeToString(y),
		}
	case *rsa.PublicKey:
		n := pub.N
		e := big.NewInt(int64(pub.E))

		return &TokenJwtKey{
			Type:     TokenJwtKeyTypeRSA,
			Exponent: base64.RawURLEncoding.EncodeToString(e.Bytes()),
			Modulus:  base64.RawURLEncoding.EncodeToString(n.Bytes()),
		}
	default:
		panic(fmt.Sprintf("unsupported key type %T", pub))
	}
}

//

func (c *TokenContainerJson) Encode(s *Token) ([]byte, error) {
	return json.Marshal(s)
}
func (c *TokenContainerJson) Decode(buf []byte) (*Token, error) {
	s := &Token{}
	err := json.Unmarshal(buf, s)
	if err != nil {
		return nil, err
	}
	return s, nil
}
func (c *TokenContainerJson) Cap() (tc TokenCap) { return tc }

func NewTokenContainerJson(c *TokenContainerJsonConfig) *TokenContainerJson {
	return &TokenContainerJson{
		Config: c,
	}
}

//

func (c *TokenContainerJwt) Encode(s *Token) ([]byte, error) {
	t := TokenJwt{
		TokenJwtMapKeyNotBefore: &jwt.NumericDate{Time: s.Header.ValidAfter},
		TokenJwtMapKeyIssuedAt:  &jwt.NumericDate{Time: s.Header.ValidAfter},
		TokenJwtMapKeyExpiresAt: &jwt.NumericDate{Time: s.Header.ValidBefore},
		TokenJwtMapKeyPayload:   s.Payload,
	}

	var (
		k  TokenMapKey
		ok bool
	)
	for key, value := range s.Header.Meta {
		k, ok = TokenJwtHeaderMapKeys[key]
		if !ok {
			k = key
		}
		t[k] = value
	}

	token, err := c.Builder.Build(t)
	if err != nil {
		return nil, err
	}

	return token.Bytes(), nil
}
func (c *TokenContainerJwt) Decode(buf []byte) (*Token, error) {
	j := TokenJwt{}
	err := jwt.ParseClaims(buf, c.Verifier, &j)
	if err != nil {
		return nil, err
	}
	t := &Token{}

	// NOTE: payload must be parsed before
	// because we destructively delete keys from original token
	// to organize them

	pm := j[TokenJwtMapKeyPayload].(map[string]interface{})
	delete(j, TokenJwtMapKeyPayload)

	p := make(TokenPayload, len(pm))
	for k, v := range pm {
		p[TokenMapKey(k)] = v
	}
	t.Payload = p

	//

	h := TokenHeader{Meta: TokenPayload{}}
	for _, key := range []TokenMapKey{
		TokenJwtMapKeyNotBefore,
		TokenJwtMapKeyIssuedAt,
		TokenJwtMapKeyExpiresAt,
	} {
		ts, ok := j[key].(float64)
		if ok {
			sec, dec := math.Modf(ts)
			tsn := time.Unix(
				int64(sec),
				int64(dec*1e19),
			)
			switch key {
			case TokenJwtMapKeyNotBefore, TokenJwtMapKeyIssuedAt:
				h.ValidAfter = tsn
			case TokenJwtMapKeyExpiresAt:
				h.ValidBefore = tsn
			}
			delete(j, key)
		}
	}

	for k, v := range j {
		h.Meta[k] = v
	}
	t.Header = h

	//

	return t, nil
}
func (c *TokenContainerJwt) Cap() (tc TokenCap) {
	tc = tc.Set(TokenCapAuthenticated)
	switch TokenJwtAlgorithms[strings.ToLower(c.Config.Algorithm)] {
	case TokenJwtAlgorithmHS256, TokenJwtAlgorithmHS384, TokenJwtAlgorithmHS512:
		tc = tc.Set(TokenCapSharedSecret)
	default:
		tc = tc.Set(TokenCapPubKeyCrypto)
	}
	return tc
}

func NewTokenContainerJwt(c *TokenContainerJwtConfig) *TokenContainerJwt {
	var (
		s   jwt.Signer
		v   jwt.Verifier
		k   TokenJwtKey
		err error
	)

	algo := TokenJwtAlgorithms[strings.ToLower(c.Algorithm)]
	switch algo {
	case TokenJwtAlgorithmHS256, TokenJwtAlgorithmHS384, TokenJwtAlgorithmHS512:
		s, err = jwt.NewSignerHS(algo, c.key)
		if err != nil {
			panic(err)
		}

		v, err = jwt.NewVerifierHS(algo, c.key)
		if err != nil {
			panic(err)
		}
	case TokenJwtAlgorithmES256, TokenJwtAlgorithmES384, TokenJwtAlgorithmES512:
		block, _ := pem.Decode(c.key)
		ecdsaPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		ecdsaPublicKey := ecdsaPrivateKey.Public().(*ecdsa.PublicKey)
		k = *NewTokenJwtKey(ecdsaPublicKey)

		s, err = jwt.NewSignerES(algo, ecdsaPrivateKey)
		if err != nil {
			panic(err)
		}

		v, err = jwt.NewVerifierES(algo, ecdsaPublicKey)
		if err != nil {
			panic(err)
		}
	case TokenJwtAlgorithmPS256, TokenJwtAlgorithmPS384, TokenJwtAlgorithmPS512:
		block, _ := pem.Decode(c.key)
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			panic(errors.Errorf("private key is not *rsa.PrivateKey, it is %T", privateKey))
		}
		rsaPublicKey := rsaPrivateKey.Public().(*rsa.PublicKey)
		k = *NewTokenJwtKey(rsaPublicKey)

		s, err = jwt.NewSignerPS(algo, rsaPrivateKey)
		if err != nil {
			panic(err)
		}

		v, err = jwt.NewVerifierPS(algo, rsaPublicKey)
		if err != nil {
			panic(err)
		}
	case TokenJwtAlgorithmRS256, TokenJwtAlgorithmRS384, TokenJwtAlgorithmRS512:
		block, _ := pem.Decode(c.key)
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			panic(errors.Errorf("private key is not *rsa.PrivateKey, it is %T", privateKey))
		}
		rsaPublicKey := rsaPrivateKey.Public().(*rsa.PublicKey)
		k = *NewTokenJwtKey(rsaPublicKey)

		s, err = jwt.NewSignerRS(algo, rsaPrivateKey)
		if err != nil {
			panic(err)
		}

		v, err = jwt.NewVerifierRS(algo, rsaPublicKey)
		if err != nil {
			panic(err)
		}
	case TokenJwtAlgorithmEdDSA:
		block, _ := pem.Decode(c.key)
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
		ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			panic(errors.Errorf("private key is not ed25519.PrivateKey, it is %T", privateKey))
		}
		ed25519PublicKey := ed25519PrivateKey.Public().(ed25519.PublicKey)
		k = *NewTokenJwtKey(ed25519PublicKey)

		s, err = jwt.NewSignerEdDSA(ed25519PrivateKey)
		if err != nil {
			panic(err)
		}

		v, err = jwt.NewVerifierEdDSA(ed25519PublicKey)
		if err != nil {
			panic(err)
		}
	default:
		panic(errors.Errorf("unsupported JWT marshaling algorithm %q", c.Algorithm))
	}

	k.Algorithm = algo
	return &TokenContainerJwt{
		Config:   c,
		Builder:  jwt.NewBuilder(s),
		Verifier: v,
		Key:      &k,
	}
}

//

func (c *TokenContainerMsgpack) Encode(s *Token) ([]byte, error) {
	return msgpack.Marshal(s)
}
func (c *TokenContainerMsgpack) Decode(buf []byte) (*Token, error) {
	s := &Token{}
	err := msgpack.Unmarshal(buf, s)
	if err != nil {
		return nil, err
	}
	return s, nil
}
func (c *TokenContainerMsgpack) Cap() (tc TokenCap) { return tc }

func NewTokenContainerMsgpack(c *TokenContainerMsgpackConfig) *TokenContainerMsgpack {
	return &TokenContainerMsgpack{
		Config: c,
	}
}

//

func (c *TokenContainerSecretBox) Encode(s *Token) ([]byte, error) {
	tokenBytes, err := c.Container.Encode(s)
	if err != nil {
		return nil, err
	}

	nonce, err := c.SecretBox.Nonce()
	if err != nil {
		return nil, err
	}
	return c.SecretBox.SealBase64(nonce, tokenBytes), nil
}
func (c *TokenContainerSecretBox) Decode(buf []byte) (*Token, error) {
	buf, err := c.SecretBox.OpenBase64(buf)
	if err != nil {
		return nil, err
	}

	return c.Container.Decode(buf)
}
func (c *TokenContainerSecretBox) Cap() (tc TokenCap) {
	tc = tc.Set(TokenCapAuthenticated)
	tc = tc.Set(TokenCapEncrypted)
	tc = tc.Set(TokenCapSharedSecret)
	return tc
}

func NewTokenContainerSecretBox(c *TokenContainerSecretBoxConfig) *TokenContainerSecretBox {
	return &TokenContainerSecretBox{
		Config:    c,
		Container: NewTokenContainer(c.Container),
		SecretBox: NewSecretBox(DefaultRand, &c.key),
	}
}

//

func NewTokenContainer(c *TokenContainerConfig) TokenContainer {
	switch strings.ToLower(c.Type) {
	case string(TokenContainerTypeJson):
		return NewTokenContainerJson(c.Json)
	case string(TokenContainerTypeJwt):
		return NewTokenContainerJwt(c.Jwt)
	case string(TokenContainerTypeMsgpack):
		return NewTokenContainerMsgpack(c.Msgpack)
	case string(TokenContainerTypeSecretBox):
		return NewTokenContainerSecretBox(c.SecretBox)
	default:
		panic(errors.Errorf("unsupported token container type: %q", c.Type))
	}
}

//

func NewTokenEncodeDecoder(t string) TokenEncodeDecoder {
	var e encoding.EncodeDecoder
	switch TokenEncodeDecoderType(strings.ToLower(t)) {
	case TokenEncodeDecoderTypeRaw:
	case TokenEncodeDecoderTypeBase64:
		e = encoding.NewEncodeDecoderBase64()
	default:
		panic(errors.Errorf("unsupported encode decoder type %q", t))
	}
	return e
}

//

func (srv TokenService) New() *Token {
	token := NewToken(srv.Config)
	for _, op := range srv.Options {
		op(token)
	}
	return token
}

func (srv TokenService) Encode(token *Token) ([]byte, error) {
	tokenBytes, err := srv.Container.Encode(token)
	if err != nil {
		return nil, err
	}
	if srv.EncodeDecoder != nil {
		return srv.EncodeDecoder.Encode(tokenBytes)
	}
	return tokenBytes, nil
}

func (srv TokenService) MustEncode(token *Token) []byte {
	buf, err := srv.Encode(token)
	if err != nil {
		panic(err)
	}
	return buf
}

func (srv TokenService) Decode(buf []byte) (*Token, error) {
	var err error
	if srv.EncodeDecoder != nil {
		buf, err = srv.EncodeDecoder.Decode(buf)
		if err != nil {
			return nil, err
		}
	}
	return srv.Container.Decode(buf)
}

func (srv TokenService) MustDecode(buf []byte) *Token {
	t, err := srv.Decode(buf)
	if err != nil {
		panic(err)
	}
	return t
}

func (srv TokenService) Validate(t *Token) error {
	if !*srv.Config.Validator.Enable {
		return nil
	}

	err := srv.Validator.Validate(t)
	if err != nil {
		return err
	}

	return nil
}

func NewTokenService(c *TokenConfig, options ...TokenServiceOption) *TokenService {
	return &TokenService{
		Config:        c,
		Options:       options,
		Container:     NewTokenContainer(c.Container),
		EncodeDecoder: NewTokenEncodeDecoder(c.Encoder),
		Validator:     NewTokenValidator(c.Validator),
	}
}
