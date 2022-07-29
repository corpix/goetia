package app

import (
	"github.com/corpix/gdk/cli"
	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/http"
	"github.com/corpix/gdk/log"
	"github.com/davecgh/go-spew/spew"

	"github.com/corpix/goetia/proxy"
)

type (
	Config struct {
		Log   *log.Config   `yaml:"log"`
		Http  *http.Config  `yaml:"http"`
		Proxy *proxy.Config `yaml:"proxy"`
	}
)

func init() {
	spew.Config.DisableMethods = false
}

//

func (c *Config) Default() {
	if c.Log == nil {
		c.Log = &log.Config{}
	}
	if c.Http == nil {
		c.Http = &http.Config{}
	}
	if c.Proxy == nil {
		c.Proxy = &proxy.Config{}
	}

	c.Http.Default()
	c.Http.Template.Templates = proxy.Templates
}

func (c *Config) Validate() error {
	return nil
}

func (c *Config) LogConfig() *log.Config     { return c.Log }
func (c *Config) HttpConfig() *http.Config   { return c.Http }
func (c *Config) ProxyConfig() *proxy.Config { return c.Proxy }

//

func WithProvideConfig(conf *Config) cli.Option {
	return func(*cli.Cli) {
		di.MustProvide(di.Default, conf.LogConfig)
		di.MustProvide(di.Default, conf.HttpConfig)
		di.MustProvide(di.Default, conf.ProxyConfig)
	}
}
