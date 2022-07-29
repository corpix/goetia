package proxy

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"io/ioutil"
	"strings"

	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/template"
)

type (
	ConnectorBasicConfig struct {
		*ConnectorConfig `yaml:",inline,omitempty"`
		Realm            string                               `yaml:"realm"`
		Users            map[string]*ConnectorBasicUserConfig `yaml:"users"`
	}
	ConnectorBasicUserConfig struct {
		Password     string `yaml:"password"`
		PasswordFile string `yaml:"password-file"`
		password     string

		Mail        string   `yaml:"mail"`
		Groups      []string `yaml:"groups"`
		DisplayName string   `yaml:"display-name"`
		AvatarUrl   string   `yaml:"avatar-url"`
	}
	ConnectorBasic struct {
		Config       *ConnectorBasicConfig
		Paths        Paths
		UserProfiles map[string]*UserProfile
	}
)

func (c *ConnectorBasicConfig) Default() {
	if c.ConnectorConfig == nil {
		c.ConnectorConfig = &ConnectorConfig{}
	}

	if c.Name == "" {
		c.Name = string(ConnectorNameBasic)
	}
	if c.Label == "" {
		c.Label = "Basic"
	}
	if c.Description == "" {
		c.Description = "HTTP Basic Auth"
	}
	if c.Realm == "" {
		c.Realm = "Restricted"
	}
}

func (c *ConnectorBasicConfig) Validate() error {
	if len(c.Users) == 0 {
		return errors.New("no users defined")
	}
	return nil
}

func (c *ConnectorBasicUserConfig) Validate() error {
	if c.Password != "" && c.PasswordFile != "" {
		return errors.New("specify either password or password-file, not both")
	}
	return nil
}

func (c *ConnectorBasicUserConfig) Expand() error {
	if c.PasswordFile != "" {
		password, err := ioutil.ReadFile(c.PasswordFile)
		if err != nil {
			return err
		}
		c.password = string(password)
	} else {
		c.password = c.Password
	}
	return nil
}

//

func (c *ConnectorBasic) Name() string        { return c.Config.Name }
func (c *ConnectorBasic) Label() string       { return c.Config.Label }
func (c *ConnectorBasic) Description() string { return c.Config.Description }

func (c *ConnectorBasic) Mount(router *http.Router) {
	router = router.PathPrefix(PathConnectors + "/" + c.Name()).Subrouter()

	di.MustInvoke(di.Default, func(t *template.Template, pr UserProfileRules) {
		router.
			HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				var err error
				session := http.RequestSessionMustGet(r)

				profile := SessionUserProfileGet(session)
				if profile == nil {
					profile, err = c.Authorize(r)
					if err != nil {
						if errors.Is(err, ErrAuthorizationRequired) {
							w.WriteHeader(http.StatusUnauthorized)
							w.Header().Set(
								http.HeaderWwwAuthenticate,
								http.AuthTypeBasic+" realm="+c.Config.Realm,
							)
							return
						}
						panic(err)
					}

					SessionUserProfileSet(session, profile, []Rule(pr)...)
					Retpath(w, r, c.Paths[PathNameStatus])
				}
			}).
			Methods(http.MethodPost)
	})
}

func (c *ConnectorBasic) Authorize(r *http.Request) (*UserProfile, error) {
	var (
		auth            = r.Header.Get(http.HeaderAuthorization)
		authTypeLen     = len(http.AuthTypeBasic)
		profilePassword = ""
	)

	if len(auth) < authTypeLen+1 || strings.EqualFold(auth[:authTypeLen], http.HeaderAuthorization) {
		return nil, errors.Wrap(
			ErrAuthorizationRequired,
			"failed to split authorization credentials from authorization header",
		)
	}

	userPasswordPairBytes, err := base64.StdEncoding.DecodeString(auth[authTypeLen+1:])
	if err != nil {
		return nil, errors.Wrap(ErrAuthorizationRequired, err.Error())
	}

	userPasswordBytesPair := bytes.SplitN(userPasswordPairBytes, []byte{':'}, 2)
	if len(userPasswordBytesPair) != 2 {
		return nil, errors.Wrapf(ErrAuthorizationRequired, "corrupted user:password pair %q", userPasswordPairBytes)
	}

	user, password := string(userPasswordBytesPair[0]), string(userPasswordBytesPair[1])
	profile, ok := c.UserProfiles[user]
	if ok {
		profilePassword = c.Config.Users[user].password
	}

	if subtle.ConstantTimeCompare(
		[]byte(password),
		[]byte(profilePassword),
	) != 1 {
		return nil, errors.Wrapf(ErrAuthorizationRequired, "passwords for user %q did not match", user)
	}
	return profile, nil
}

func NewConnectorBasic(c *ConnectorBasicConfig, p Paths) *ConnectorBasic {
	connector := &ConnectorBasic{
		Config:       c,
		Paths:        p,
		UserProfiles: map[string]*UserProfile{},
	}
	for name, user := range c.Users {
		connector.UserProfiles[name] = &UserProfile{
			Connector:   string(ConnectorNameBasic),
			Name:        name,
			DisplayName: user.DisplayName,
			Mail:        user.Mail,
			Groups:      user.Groups,
			AvatarUrl:   user.AvatarUrl,
		}
	}
	return connector
}
