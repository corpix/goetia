package http

import (
	"github.com/gorilla/mux"

	"github.com/corpix/gdk/errors"
)

type (
	Router         = mux.Router
	RouteWalkFn    = mux.WalkFunc
	Route          = mux.Route
	RouteMatch     = mux.RouteMatch
	MiddlewareFunc = mux.MiddlewareFunc
)

var (
	SetURLVars   = mux.SetURLVars
	GetURLVars   = mux.Vars
	CurrentRoute = mux.CurrentRoute
)

func RoutePathTemplate[T ~string](router *Router, name T) string {
	route := router.Get(string(name))
	if route == nil {
		panic(errors.Errorf("no route with name %q", name))
	}
	routePath, err := route.GetPathTemplate()
	if err != nil {
		panic(err)
	}
	return routePath
}

func NewRouter(c *Config) *Router {
	r := mux.NewRouter()
	if c.Prefix != "" {
		r = r.PathPrefix(c.Prefix).Subrouter()
	}
	return r
}
