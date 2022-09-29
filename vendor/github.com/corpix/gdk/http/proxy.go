package http

import (
	"context"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/corpix/gdk/errors"
)

type (
	ReverseProxy = httputil.ReverseProxy

	ProxyConfig struct {
		Enable    bool                `yaml:"enable"`
		Upstreams map[string]string   `yaml:"upstreams"`
		Locations map[string]struct{} `yaml:"locations"`
	}
	Proxy struct {
		Config    *ProxyConfig
		Balancer  ProxyBalancer
		Predicate func(*Http, ResponseWriter, *Request) bool
	}
	ProxyOption func(*Proxy)

	ProxyUpstream struct {
		Name string
		Url  *url.URL
	}
	ProxyBalancer interface {
		Dispatch(*Request) *ReverseProxy
	}
	ProxyBalancerRoundRobin struct {
		Upstreams       []*ProxyUpstream
		UpstreamProxies []*ReverseProxy
		State           uint32
	}
)

//

func (c *ProxyConfig) Default() {
	if !c.Enable {
		return
	}
	if len(c.Locations) == 0 {
		c.Locations = map[string]struct{}{
			"/{_:.*}": {},
		}
	}
}

func (c *ProxyConfig) Validate() error {
	if !c.Enable {
		return nil
	}
	if len(c.Upstreams) == 0 {
		return errors.New(`upstreams should contain one or more upstreams in a form "name: schema://host/path"`)
	}
	return nil
}

//

func NewReverseProxy(u *ProxyUpstream) *ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(u.Url)
	proxy.ErrorHandler = func(w ResponseWriter, r *Request, err error) {
		if err == context.Canceled || strings.Contains(err.Error(), "operation was canceled") {
			w.WriteHeader(StatusCanceled)
		} else {
			l := RequestLogGet(r)
			l.Error().
				Str("url", r.URL.String()).
				Str("upstream-name", u.Name).
				Str("upstream", u.Url.String()).
				Err(err).
				Msg("failed to proxy request")
			w.WriteHeader(StatusBadGateway)
		}
	}
	return proxy
}

func NewProxyBalancerRoundRobin(us []*ProxyUpstream) *ProxyBalancerRoundRobin {
	ps := make([]*httputil.ReverseProxy, len(us))
	for n, upstream := range us {
		ps[n] = NewReverseProxy(upstream)
	}
	return &ProxyBalancerRoundRobin{
		Upstreams:       us,
		UpstreamProxies: ps,
	}
}

func (b *ProxyBalancerRoundRobin) Dispatch(r *Request) *ReverseProxy {
	atomic.AddUint32(&b.State, 1)
	return b.UpstreamProxies[b.State%uint32(len(b.Upstreams))]
}

//

func WithProxy(c *ProxyConfig, options ...ProxyOption) Option {
	p := NewProxy(c, options...)
	return func(h *Http) {
		for location := range c.Locations {
			h.Router.HandleFunc(location, func(w ResponseWriter, r *Request) {
				if p.Predicate != nil {
					if !p.Predicate(h, w, r) {
						return
					}
				}
				p.Balancer.Dispatch(r).ServeHTTP(w, r)
			})
		}
	}
}

func WithProxyPredicate(pred func(*Http, ResponseWriter, *Request) bool) ProxyOption {
	return func(p *Proxy) {
		p.Predicate = pred
	}
}

//

func NewProxy(c *ProxyConfig, options ...ProxyOption) *Proxy {
	upstreams := make([]*ProxyUpstream, len(c.Upstreams))
	n := 0
	for name, upstream := range c.Upstreams {
		u, err := url.Parse(upstream)
		if err != nil {
			panic(err)
		}
		upstreams[n] = &ProxyUpstream{
			Name: name,
			Url:  u,
		}
		n++
	}

	p := &Proxy{
		Config:   c,
		Balancer: NewProxyBalancerRoundRobin(upstreams),
	}
	for _, option := range options {
		option(p)
	}
	return p
}
