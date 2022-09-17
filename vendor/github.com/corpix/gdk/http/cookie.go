package http

import (
	"net/http"
)

type (
	Cookie             = http.Cookie
	CookieSameSiteMode = http.SameSite
)

const (
	CookieSameSiteDefaultMode = CookieSameSiteMode(http.SameSiteDefaultMode)
	CookieSameSiteLaxMode     = CookieSameSiteMode(http.SameSiteLaxMode)
	CookieSameSiteStrictMode  = CookieSameSiteMode(http.SameSiteStrictMode)
	CookieSameSiteNoneMode    = CookieSameSiteMode(http.SameSiteNoneMode)
)

var (
	CookieSameSiteModesString = map[CookieSameSiteMode]string{
		CookieSameSiteDefaultMode: "default",
		CookieSameSiteLaxMode:     "lax",
		CookieSameSiteStrictMode:  "strict",
		CookieSameSiteNoneMode:    "none",
	}
	CookieSameSiteModes = map[string]CookieSameSiteMode{}
)

//

func CookieSet(w ResponseWriter, cookie *Cookie) {
	http.SetCookie(w, cookie)
}

func CookieGet(r *Request, name string) (*Cookie, error) {
	return r.Cookie(name)
}

//

func init() {
	for key, value := range CookieSameSiteModesString {
		CookieSameSiteModes[value] = key
	}
}
