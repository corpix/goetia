package main

import (
	"github.com/corpix/gdk/cli"
	"github.com/corpix/gdk/config"
	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/http"

	"github.com/corpix/goetia/app"
	"github.com/corpix/goetia/proxy"
)

var conf = &app.Config{}

func main() {
	di.MustProvide(di.Default, proxy.ErrorHandlerCtr)

	cli.New(
		cli.WithName("goetia"),
		cli.WithUsage("Auth broker"),
		cli.WithDescription("Auth broker server supporting configurable authentication providers"),
		cli.WithConfigTools(
			conf,
			config.YamlUnmarshaler,
			config.YamlMarshaler,
		),
		app.WithProvideConfig(conf),
		cli.WithLogTools(conf.LogConfig),
		cli.WithHttpTools(
			conf.HttpConfig,
			http.WithInvoke(di.Default, proxy.Serve),
		),
	).RunAndExitOnError()
}

//

/*
   context keys:
   - requestId (current req id)
   - container (document content container)
   - error (error message)
   - session *user session
   - connectors, providers (list of enabled connectors, providers)
   - paths (goetia pages for routing)
   - user (user profile + any other information about user, like provider)
*/
