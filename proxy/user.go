package proxy

import (
	"fmt"
	"net/url"

	"github.com/itchyny/gojq"

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
	UserProfileHeadersService struct {
		Config *UserProfileHeadersConfig
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

func (c *UserConfig) Default() {
	if c.Profile == nil {
		c.Profile = &UserProfileConfig{}
	}
	if c.Retpath == nil {
		c.Retpath = &UserRetpathConfig{}
	}
}

func (c *UserProfileConfig) Default() {
	if c.Headers == nil {
		c.Headers = &UserProfileHeadersConfig{}
	}
}

const (
	UserProfileConnector   = "connector"
	UserProfileName        = "name"
	UserProfileMail        = "mail"
	UserProfileGroups      = "groups"
	UserProfileDisplayName = "display-name"
	UserProfileAvatarUrl   = "avatar-url"

	UserRetpathQueryKey = "retpath"

	SessionMapKeyUserProfile http.SessionMapKey = "user-profile"
	SessionMapKeyUserRetpath http.SessionMapKey = "user-retpath"
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

func (srv *UserProfileHeadersService) SkipPaths(paths ...string) {
	for _, path := range paths {
		srv.Config.SkipPaths[path] = struct{}{}
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

func (p *UserProfile) Map() map[string]interface{} {
	return map[string]interface{}{
		UserProfileConnector:   p.Connector,
		UserProfileName:        p.Name,
		UserProfileMail:        p.Mail,
		UserProfileGroups:      p.Groups,
		UserProfileDisplayName: p.DisplayName,
		UserProfileAvatarUrl:   p.AvatarUrl,
	}
}

func UserProfileMap(profile map[string]interface{}, mapping map[string]string) map[string]interface{} {
	var (
		v      interface{}
		ok     bool
		mapped = make(map[string]interface{}, len(mapping))
	)
	for from, to := range mapping {
		v, ok = profile[from]
		if !ok {
			continue
		}
		mapped[to] = v
	}
	return mapped
}

func UserProfileMapReversed(profile map[string]interface{}, mapping map[string]string) map[string]interface{} {
	var (
		v      interface{}
		ok     bool
		mapped = make(map[string]interface{}, len(mapping))
	)
	for to, from := range mapping {
		v, ok = profile[from]
		if !ok {
			continue
		}
		mapped[to] = v
	}
	return mapped
}

func UserProfileRemap(profile map[string]interface{}, mapping map[string]string) map[string]interface{} {
	var (
		key      string
		remapped = make(map[string]interface{}, len(profile))
	)
	for k, v := range profile {
		key = mapping[k]
		if key != "" {
			remapped[key] = v
		}
	}
	return remapped
}

func (p *UserProfile) Remap(mapping map[string]string) map[string]interface{} {
	return UserProfileRemap(p.Map(), mapping)
}

// NOTE: it is working only with map[]interface{} because of asserts in gojq
func UserProfileExpand(profile map[string]interface{}, expr *gojq.Query) map[string]interface{} {
	iter := expr.Run(profile)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			panic(err)
		}
		return v.(map[string]interface{})
	}
	panic("user profile expand expression returned nothing")
}

func (p *UserProfile) Expand(expr *gojq.Query) interface{} {
	return UserProfileExpand(p.Map(), expr)
}

//

func UserProfileHeaderSet(headers http.Header, profile *UserProfile, remap map[string]string) {
	for k, v := range profile.Remap(remap) {
		headers.Set(k, fmt.Sprintf("%s", v))
	}
}

func MiddlewareUserProfileHeaders(srv *UserProfileHeadersService) http.Middleware {
	setReq, setRes := *srv.Config.Request, *srv.Config.Response
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if http.Skip(srv.Config.SkipConfig, r) {
				h.ServeHTTP(w, r)
				return
			}

			session := http.RequestSessionMustGet(r)

			var profile *UserProfile
			if setReq {
				profile = SessionUserProfileGet(session)
				if profile != nil {
					UserProfileHeaderSet(r.Header, profile, srv.Config.Map)
				}
			}
			h.ServeHTTP(w, r)
			if setRes {
				profile = SessionUserProfileGet(session)
				if profile != nil {
					UserProfileHeaderSet(w.Header(), profile, srv.Config.Map)
				}
			}
		})
	}
}

func NewUserProfileHeadersService(c *UserProfileHeadersConfig) *UserProfileHeadersService {
	return &UserProfileHeadersService{Config: c}
}

//

func NewUserProfileRules(c []*RuleConfig) UserProfileRules {
	return UserProfileRules(NewRules(c))
}

func SessionUserProfileGet(session *http.Session) *UserProfile {
	rawProfile, ok := session.Get(SessionMapKeyUserProfile)
	if !ok {
		return nil
	}
	profile := rawProfile.(map[string]interface{})

	rawGroups := profile[UserProfileGroups]
	var groups []string
	switch g := rawGroups.(type) {
	case []interface{}:
		groups = make([]string, len(g))
		for n, v := range g {
			groups[n] = v.(string)
		}
	case []string:
		groups = g
	}

	return &UserProfile{
		Connector:   profile[UserProfileConnector].(string),
		Name:        profile[UserProfileName].(string),
		DisplayName: profile[UserProfileDisplayName].(string),
		Mail:        profile[UserProfileMail].(string),
		Groups:      groups,
		AvatarUrl:   profile[UserProfileAvatarUrl].(string),
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

func SessionUserProfileSetMap(session *http.Session, profile map[string]interface{}, rules ...Rule) {
	if len(rules) > 0 {
		err := RulesMatch(profile, rules...)
		if err != nil {
			panic(err)
		}
	}
	session.Set(SessionMapKeyUserProfile, profile)
}

func SessionUserProfileSet(session *http.Session, profile *UserProfile, rules ...Rule) {
	SessionUserProfileSetMap(session, profile.Map(), rules...)
}

func SessionUserProfileDel(session *http.Session) {
	session.Del(SessionMapKeyUserProfile)
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
	rawRetpath, ok := session.Get(SessionMapKeyUserRetpath)
	if !ok {
		return ""
	}

	return rawRetpath.(string)
}

func SessionUserRetpathSet(session *http.Session, retpath string) {
	session.Set(SessionMapKeyUserRetpath, retpath)
}

func SessionUserRetpathDel(session *http.Session) {
	session.Del(SessionMapKeyUserRetpath)
}

func RequestUserRetpathGet(r *http.Request) string {
	return r.URL.Query().Get(UserRetpathQueryKey)
}
