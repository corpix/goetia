package http

import (
	"crypto/subtle"
	"io/ioutil"
	"strings"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/corpix/gdk/errors"
	"github.com/corpix/gdk/log"
	"github.com/corpix/gdk/metrics"
)

type (
	MetricsOption        = promhttp.Option
	MetricsHandlerConfig = promhttp.HandlerOpts
)

var (
	MetricsHandlerDuration     = promhttp.InstrumentHandlerDuration
	MetricsHandlerCounter      = promhttp.InstrumentHandlerCounter
	MetricsHandlerRequestSize  = promhttp.InstrumentHandlerRequestSize
	MetricsHandlerResponseSize = promhttp.InstrumentHandlerResponseSize
	MetricsHandlerInFlight     = promhttp.InstrumentHandlerInFlight

	MetricsHandler    = promhttp.InstrumentMetricHandler
	MetricsHandlerFor = promhttp.HandlerFor
)

//

type MetricsConfig struct {
	Enable    bool   `yaml:"enable"`
	Path      string `yaml:"path"`
	AuthType  string `yaml:"auth-type"`
	Token     string `yaml:"token"`
	TokenFile string `yaml:"token-file"`
	token     string

	*SkipConfig `yaml:",inline,omitempty"`
}

func (c *MetricsConfig) Default() {
	if c.Path == "" {
		c.Path = "/metrics"
	}
	if c.AuthType == "" {
		c.AuthType = AuthTypeBearer
	}

	if c.SkipConfig == nil {
		c.SkipConfig = &SkipConfig{}
	}
}

func (c *MetricsConfig) Validate() error {
	if c.Token != "" && c.TokenFile != "" {
		return errors.New("either define token or token-file, not both of them")
	}

	if strings.ToLower(c.AuthType) != AuthTypeBearer {
		// TODO: more token types + token encoding? not sure we need it now, but in future... maybe
		return errors.New("at this moment only bearer token type is supported")
	}
	return nil
}

func (c *MetricsConfig) Expand() error {
	c.AuthType = strings.ToLower(c.AuthType)

	// FIXME: expansion called multiple times? why?
	if c.TokenFile != "" {
		tokenBytes, err := ioutil.ReadFile(c.TokenFile)
		if err != nil {
			return errors.Wrapf(err, "failed to read token file at %q", c.TokenFile)
		}
		c.token = string(tokenBytes)
	} else {
		c.token = c.Token
	}
	return nil
}

//

func MiddlewareMetrics(c *MetricsConfig, options ...MetricsOption) Middleware {
	labels := []string{
		"code",
		"method",
	}

	duration := metrics.NewHistogramVec(metrics.HistogramOpts{
		Name: "request_duration_histogram_seconds",
		Help: "Request time duration.",
	}, labels)
	total := metrics.NewCounterVec(metrics.CounterOpts{
		Name: "requests_total",
		Help: "Total number of requests received.",
	}, labels)
	reqSize := metrics.NewHistogramVec(metrics.HistogramOpts{
		Name:    "request_size_histogram_bytes",
		Help:    "Request size in bytes.",
		Buckets: []float64{100, 1000, 2000, 5000, 10000},
	}, labels)
	resSize := metrics.NewHistogramVec(metrics.HistogramOpts{
		Name:    "response_size_histogram_bytes",
		Help:    "Response size in bytes.",
		Buckets: []float64{100, 1000, 2000, 5000, 10000},
	}, labels)
	inFlight := metrics.NewGauge(metrics.GaugeOpts{
		Name: "requests_in_flight",
		Help: "Number of http requests which are currently running.",
	})

	metrics.MustRegister(
		duration,
		total,
		reqSize,
		resSize,
		inFlight,
	)

	return func(h Handler) Handler {
		next := MetricsHandlerDuration(duration,
			MetricsHandlerCounter(total,
				MetricsHandlerRequestSize(reqSize,
					MetricsHandlerResponseSize(resSize,
						MetricsHandlerInFlight(inFlight, h),
						options...,
					),
					options...,
				),
				options...,
			),
			options...,
		)

		return HandlerFunc(func(w ResponseWriter, r *Request) {
			if Skip(c.SkipConfig, r) {
				h.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func WithMetricsHandler(registry metrics.RegisterGatherer) Option {
	return func(h *Http) {
		if !h.Config.Metrics.Enable {
			return
		}

		var (
			handler    Handler
			rawHandler = MetricsHandler(registry, MetricsHandlerFor(registry,
				MetricsHandlerConfig{ErrorLog: log.Std(log.Default)},
			))
			r = h.Router.NewRoute().
				Methods(MethodGet).
				Path(h.Config.Metrics.Path)
			token = h.Config.Metrics.token
		)

		if token == "" {
			log.Warn().
				Msg("metrics token is not defined, (very likely this is not what you want, so) please define metrics.token or metrics.token-file")

			handler = rawHandler
		} else {
			subjectAuthorization := h.Config.Metrics.AuthType + " " + token
			handler = HandlerFunc(func(w ResponseWriter, r *Request) {
				clientAuthorization := r.Header.Get(HeaderAuthorization)
				if subtle.ConstantTimeCompare(
					[]byte(subjectAuthorization),
					[]byte(clientAuthorization),
				) == 1 {
					rawHandler.ServeHTTP(w, r)
					return
				}

				l := RequestLogGet(r)
				l.Warn().Msg("authentication failed, token does not match")

				w.WriteHeader(StatusNotFound)
			})
		}

		r.Handler(handler)
	}
}
