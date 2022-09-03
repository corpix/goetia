package proxy

import (
	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/http"
)

func RoutePathTemplate[T ~string](router *http.Router, name T) string {
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
