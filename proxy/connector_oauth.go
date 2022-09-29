package proxy

import (
	"encoding/json"
	"math"
	"math/big"
	gohttp "net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/corpix/gdk/crypto"
	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/log"
	"github.com/corpix/gdk/template"
)

type (
	ConnectorOauthConfig struct {
		*ConnectorConfig `yaml:",inline,omitempty"`

		AuthorizeUrl string `yaml:"authorize-url"`
		TokenUrl     string `yaml:"token-url"`
		RedirectUrl  string `yaml:"redirect-url"`
		ProfileUrl   string `yaml:"profile-url"`

		codeUrl     *url.URL
		tokenUrl    *url.URL
		redirectUrl *url.URL
		profileUrl  *url.URL

		ClientId   string                                 `yaml:"client-id"`
		Profile    *ProviderOauthApplicationProfileConfig `yaml:"profile"`
		StateToken *crypto.TokenConfig                    `yaml:"state-token"`
	}
	ConnectorOauth struct {
		Config            *ConnectorOauthConfig
		StateTokenService *crypto.TokenService
	}
)

func (c *ConnectorOauthConfig) Default() {
	if c.ConnectorConfig == nil {
		c.ConnectorConfig = &ConnectorConfig{}
	}

	if c.Name == "" {
		c.Name = string(ConnectorNameOauth)
	}
	if c.Label == "" {
		c.Label = "OAuth"
	}
	if c.Description == "" {
		c.Description = "HTTP OAuth2 flow connector"
	}

	if c.Profile == nil {
		c.Profile = &ProviderOauthApplicationProfileConfig{}
	}

	if c.StateToken == nil {
		c.StateToken = &crypto.TokenConfig{}
	}
	c.StateToken.Default()
	c.StateToken.Validator.Default()
	c.StateToken.Validator.Expire = &crypto.TokenValidatorExpireConfig{}
	if c.StateToken.Validator.Expire.MaxAge == nil {
		dur := 30 * time.Minute
		c.StateToken.Validator.Expire.MaxAge = &dur
	}
	if c.StateToken.Validator.Expire.TimeDrift == nil {
		dur := 30 * time.Second
		c.StateToken.Validator.Expire.TimeDrift = &dur
	}
}

func (c *ConnectorOauthConfig) Validate() error {
	if c.AuthorizeUrl == "" {
		return errors.New("authorize-url should not be empty")
	}
	if c.TokenUrl == "" {
		return errors.New("token-url should not be empty")
	}
	if c.RedirectUrl == "" {
		return errors.New("redirect-url should not be empty")
	}
	if c.ProfileUrl == "" {
		return errors.New("profile-url should not be empty")
	}

	if c.ClientId == "" {
		return errors.New("client-id should not be empty")
	}

	return nil
}

func (c *ConnectorOauthConfig) Expand() error {
	var err error

	c.codeUrl, err = url.Parse(c.AuthorizeUrl)
	if err != nil {
		return err
	}
	c.tokenUrl, err = url.Parse(c.TokenUrl)
	if err != nil {
		return err
	}
	c.redirectUrl, err = url.Parse(c.RedirectUrl)
	if err != nil {
		return err
	}
	c.profileUrl, err = url.Parse(c.ProfileUrl)
	if err != nil {
		return err
	}
	return nil
}

//

func (c *ConnectorOauth) Name() string        { return c.Config.Name }
func (c *ConnectorOauth) Label() string       { return c.Config.Label }
func (c *ConnectorOauth) Description() string { return c.Config.Description }

func (c *ConnectorOauth) Mount(router *http.Router) {
	di.MustInvoke(di.Default, func(
		t *template.Template,
		profileRules UserProfileRules,
		paths Paths,
	) {
		router.
			HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				nonce, err := crypto.RandInt(big.NewInt(math.MaxInt64))
				if err != nil {
					panic(err)
				}
				nonceStr := strconv.FormatInt(nonce.Int64(), 10)

				session := http.RequestSessionMustGet(r)
				session.Set(SessionMapKeyOauthStateNonce, nonceStr)

				u := *c.Config.codeUrl
				q := u.Query()

				t := c.StateTokenService.New()
				t.Set(SessionMapKeyOauthStateNonce, nonceStr)

				q.Add(string(OauthParameterClientId), c.Config.ClientId)
				q.Add(string(OauthParameterRedirectUri), c.Config.redirectUrl.String())
				q.Add(string(OauthParameterState), string(c.StateTokenService.MustEncode(t)))
				u.RawQuery = q.Encode()

				http.Redirect(w, r, u.String(), http.StatusFound)
			}).
			Methods(http.MethodPost)

		router.
			HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				state := q.Get(string(OauthParameterState))

				t := c.StateTokenService.MustDecode([]byte(state))
				stateNonce := t.MustGet(SessionMapKeyOauthStateNonce).(string)

				session := http.RequestSessionMustGet(r)
				sessionNonce := session.MustGet(SessionMapKeyOauthStateNonce).(string)

				if stateNonce != sessionNonce {
					log.Warn().
						Str("state-nonce", stateNonce).
						Str("session-nonce", sessionNonce).
						Msg("state nonce does not match session nonce")
					panic(errors.New("corrupted state"))
				}

				//

				code := q.Get(string(OauthParameterCode))

				form := url.Values{}
				form.Add(string(OauthParameterCode), code)
				tokenResp, err := gohttp.PostForm(c.Config.tokenUrl.String(), form)
				if err != nil {
					panic(err)
				}
				defer tokenResp.Body.Close()

				oauthToken := &OauthTokenResponse{}
				err = json.NewDecoder(tokenResp.Body).Decode(oauthToken)
				if err != nil {
					panic(err)
				}

				//

				req, err := gohttp.NewRequest(
					http.MethodGet,
					c.Config.profileUrl.String(),
					nil,
				)
				if err != nil {
					panic(err)
				}
				req.Header.Add(
					http.HeaderAuthorization,
					http.AuthTypeBearer+" "+oauthToken.AccessToken,
				)
				profileResp, err := gohttp.DefaultClient.Do(req)
				if err != nil {
					panic(err)
				}
				defer profileResp.Body.Close()

				rawProfile := map[string]interface{}{}
				err = json.NewDecoder(profileResp.Body).Decode(&rawProfile)
				if err != nil {
					panic(err)
				}

				profile := c.UserProfileExpandRemap(rawProfile)
				SessionUserProfileSetMap(session, profile, []Rule(profileRules)...)
				Retpath(w, r, paths[PathNameStatus])
			}).
			Methods(http.MethodGet)
	})
}

func (c *ConnectorOauth) UserProfileExpandRemap(profile map[string]interface{}) map[string]interface{} {
	rm := UserProfileMapReversed(profile, c.Config.Profile.Map)
	if c.Config.Profile.expandExpr == nil {
		return rm
	}
	return UserProfileExpand(rm, c.Config.Profile.expandExpr)
}

func NewConnectorOauth(c *ConnectorOauthConfig) *ConnectorOauth {
	connector := &ConnectorOauth{
		Config:            c,
		StateTokenService: crypto.NewTokenService(c.StateToken),
	}
	return connector
}
