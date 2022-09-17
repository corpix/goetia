package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type (
	Registry   = prometheus.Registry
	Registerer = prometheus.Registerer
	Gatherer   = prometheus.Gatherer

	RegisterGatherer interface {
		Registerer
		Gatherer
	}

	Counter     = prometheus.Counter
	CounterVec  = prometheus.CounterVec
	CounterOpts = prometheus.CounterOpts

	Gauge     = prometheus.Gauge
	GaugeVec  = prometheus.GaugeVec
	GaugeOpts = prometheus.GaugeOpts

	Histogram     = prometheus.Histogram
	HistogramVec  = prometheus.HistogramVec
	HistogramOpts = prometheus.HistogramOpts

	Labels = prometheus.Labels
)

var (
	NewRegistry                        = prometheus.NewRegistry
	DefaultRegisterer                  = prometheus.DefaultRegisterer
	DefaultGatherer                    = prometheus.DefaultGatherer
	Default           RegisterGatherer = struct {
		Registerer
		Gatherer
	}{
		Registerer: DefaultRegisterer,
		Gatherer:   DefaultGatherer,
	}
	MustRegister = prometheus.MustRegister
	Register     = prometheus.Register

	NewCounter      = prometheus.NewCounter
	NewCounterVec   = prometheus.NewCounterVec
	NewGauge        = prometheus.NewGauge
	NewGaugeVec     = prometheus.NewGaugeVec
	NewHistogram    = prometheus.NewHistogram
	NewHistogramVec = prometheus.NewHistogramVec
)
