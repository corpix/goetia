package proxy

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/corpix/gdk/http"
)

type (
	UserConfig struct {
		Profile *UserProfileConfig `yaml:"profile"`
		Retpath *UserRetpathConfig `yaml:"retpath"`
	}
	UserProfileConfig struct {
		Rules   []*RuleConfig             `yaml:"rules"`
		Headers *UserProfileHeadersConfig `yaml:"headers"`
	}
	UserProfileRules         []Rule
	UserProfileHeadersConfig struct {
		Enable           bool              `yaml:"enable"`
		Map              map[string]string `yaml:"map"`
		Request          *bool             `yaml:"request"`
		Response         *bool             `yaml:"response"`
		*http.SkipConfig `yaml:",inline"`
	}
	UserRetpathConfig struct {
		Rules []*RuleConfig `yaml:"rules"`
	}
	UserProfileRetpathRules []Rule

	UserProfile struct {
		Connector   string   `json:"connector"`
		Name        string   `json:"name"`
		DisplayName string   `json:"display-name,omitempty"`
		Mail        string   `json:"mail"`
		Groups      []string `json:"groups,omitempty"`
		AvatarUrl   string   `json:"avatar-url,omitempty"`
	}
)

const (
	UserProfileConnector   = "connector"
	UserProfileName        = "name"
	UserProfileMail        = "mail"
	UserProfileGroups      = "groups"
	UserProfileDisplayName = "display-name"
	UserProfileAvatarUrl   = "avatar-url"

	UserRetpathQueryKey = "retpath"

	SessionPayloadKeyUserProfile http.SessionPayloadKey = "user-profile"
	SessionPayloadKeyUserRetpath http.SessionPayloadKey = "user-retpath"
)

var (
	UserProfileKeys = []string{
		UserProfileConnector,
		UserProfileName,
		UserProfileMail,
		UserProfileGroups,
		UserProfileDisplayName,
		UserProfileAvatarUrl,
	}
)

//

func (c *UserProfileHeadersConfig) Default() {
	if !c.Enable {
		return
	}
	if c.Map == nil {
		c.Map = map[string]string{}
	}
	for _, key := range UserProfileKeys {
		_, ok := c.Map[key]
		if !ok {
			c.Map[key] = "x-auth-" + key
		}
	}

	if c.Request == nil {
		v := true
		c.Request = &v
	}
	if c.Response == nil {
		v := true
		c.Response = &v
	}

	if c.SkipConfig == nil {
		c.SkipConfig = &http.SkipConfig{}
	}
}

func (c *UserRetpathConfig) Default() {
	if len(c.Rules) == 0 {
		c.Rules = []*RuleConfig{
			{
				// NOTE: imply "only local" rule by default
				// to mitigate retpaths like http://evil.com
				Type: string(RuleTypeRegexp),
				Expr: "^/.*$",
			},
		}
	}
}

func (p *UserProfile) Map() map[string]string {
	return map[string]string{
		UserProfileConnector:   p.Connector,
		UserProfileName:        p.Name,
		UserProfileMail:        p.Mail,
		UserProfileGroups:      strings.Join(p.Groups, ","),
		UserProfileDisplayName: p.DisplayName,
		UserProfileAvatarUrl:   p.AvatarUrl,
	}
}

func (p *UserProfile) MapInterface() map[string]interface{} {
	m := p.Map()
	rm := make(map[string]interface{}, len(m))
	for k, v := range m {
		rm[k] = v
	}
	return rm
}

func (p *UserProfile) Remap(mapping map[string]string) map[string]string {
	var (
		key      string
		profile  = p.Map()
		remapped = make(map[string]string, len(profile))
	)
	for k, v := range profile {
		key = mapping[k]
		if key != "" {
			remapped[key] = v
		}
	}
	return remapped
}

//

func UserProfileHeaderSet(headers http.Header, profile *UserProfile, remap map[string]string) {
	for k, v := range profile.Remap(remap) {
		headers.Set(k, v)
	}
}

func MiddlewareUserProfileHeaders(c *UserProfileHeadersConfig) http.Middleware {
	setReq, setRes := *c.Request, *c.Response
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if http.Skip(c.SkipConfig, r) {
				h.ServeHTTP(w, r)
				return
			}

			session := http.RequestSessionMustGet(r)

			var profile *UserProfile
			if setReq {
				profile = SessionUserProfileGet(session)
				if profile != nil {
					UserProfileHeaderSet(r.Header, profile, c.Map)
				}
			}
			h.ServeHTTP(w, r)
			if setRes {
				profile = SessionUserProfileGet(session)
				if profile != nil {
					UserProfileHeaderSet(w.Header(), profile, c.Map)
				}
			}
		})
	}
}

//

func NewUserProfileRules(c []*RuleConfig) UserProfileRules {
	return UserProfileRules(NewRules(c))
}

func SessionUserProfileGet(session *http.Session) *UserProfile {
	rawProfile, ok := session.Get(string(SessionPayloadKeyUserProfile))
	if !ok {
		return nil
	}

	profile := map[string]string{}
	switch p := rawProfile.(type) {
	case map[string]interface{}:
		for k, v := range p {
			profile[k] = v.(string)
		}
	case map[string]string:
		profile = p
	default:
		panic(fmt.Sprintf("unsupported profile map type %T", rawProfile))
	}

	return &UserProfile{
		Connector:   profile[UserProfileConnector],
		Name:        profile[UserProfileName],
		DisplayName: profile[UserProfileDisplayName],
		Mail:        profile[UserProfileMail],
		Groups:      strings.Split(profile[UserProfileGroups], ","),
		AvatarUrl:   profile[UserProfileAvatarUrl],
	}
}

func SessionUserProfileGetOrRedirect(w http.ResponseWriter, r *http.Request, session *http.Session, signin string) *UserProfile {
	profile := SessionUserProfileGet(session)
	if profile == nil {
		u := &url.URL{Path: signin}
		u.Query().Set(UserRetpathQueryKey, r.URL.String())
		http.Redirect(w, r, u.String(), http.StatusFound)
		return nil
	}
	return profile
}

func SessionUserProfileSet(session *http.Session, profile *UserProfile, rules ...Rule) {
	m := profile.Map()
	if len(rules) > 0 {
		err := RulesMatch(m, rules...)
		if err != nil {
			panic(err)
		}
	}
	session.Set(string(SessionPayloadKeyUserProfile), m)
}

func SessionUserProfileDel(session *http.Session) {
	session.Del(string(SessionPayloadKeyUserProfile))
}

//

func NewUserProfileRetpathRules(c []*RuleConfig) UserProfileRetpathRules {
	return UserProfileRetpathRules(NewRules(c))
}

func Retpath(w http.ResponseWriter, r *http.Request, fallback string) {
	session := http.RequestSessionMustGet(r)
	retpath := SessionUserRetpathGet(session)
	if retpath == "" {
		if fallback == "" {
			retpath = "/"
		} else {
			retpath = fallback
		}
	} else {
		SessionUserRetpathDel(session)
	}
	http.Redirect(w, r, retpath, http.StatusFound)
}

func SessionUserRetpathGet(session *http.Session) string {
	rawRetpath, ok := session.Get(string(SessionPayloadKeyUserRetpath))
	if !ok {
		return ""
	}

	return rawRetpath.(string)
}

func SessionUserRetpathSet(session *http.Session, retpath string) {
	session.Set(string(SessionPayloadKeyUserRetpath), retpath)
}

func SessionUserRetpathDel(session *http.Session) {
	session.Del(string(SessionPayloadKeyUserRetpath))
}

func RequestUserRetpathGet(r *http.Request) string {
	return r.URL.Query().Get(UserRetpathQueryKey)
}
