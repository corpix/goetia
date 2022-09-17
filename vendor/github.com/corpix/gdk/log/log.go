package log

import (
	"io"
	"os"

	console "github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"

	"github.com/corpix/gdk/di"
	"github.com/corpix/gdk/errors"
)

type (
	Level    = zerolog.Level
	Logger   = zerolog.Logger
	Option   func(*Logger)
	Context  = zerolog.Context
	Hook     = zerolog.Hook
	HookFunc = zerolog.HookFunc

	Event          = zerolog.Event
	EventDecorator interface {
		DecorateEvent(e *Event)
	}
	EventDecoratorError struct {
		Err  error
		Meta map[string]interface{}
	}
)

const (
	LevelTrace = zerolog.TraceLevel
	LevelDebug = zerolog.DebugLevel
	LevelInfo  = zerolog.InfoLevel
	LevelWarn  = zerolog.WarnLevel
	LevelError = zerolog.ErrorLevel
	LevelPanic = zerolog.PanicLevel
	LevelFatal = zerolog.FatalLevel
)

type Config struct {
	Level string `yaml:"level"`
}

func (c *Config) Default() {
	if c.Level == "" {
		c.Level = LevelInfo.String()
	}
}

//

var Default Logger

func Debug() *Event                                { return Default.Debug() }
func Err(err error) *Event                         { return Default.Err(err) }
func Error() *Event                                { return Default.Error() }
func Fatal() *Event                                { return Default.Fatal() }
func Info() *Event                                 { return Default.Info() }
func Log() *Event                                  { return Default.Log() }
func Panic() *Event                                { return Default.Panic() }
func Print(v ...interface{})                       { Default.Print(v...) }
func Printf(format string, v ...interface{})       { Default.Printf(format, v...) }
func Trace() *Event                                { return Default.Trace() }
func UpdateContext(update func(c Context) Context) { Default.UpdateContext(update) }
func Warn() *Event                                 { return Default.Warn() }
func WithLevel(level Level) *Event                 { return Default.WithLevel(level) }
func With() Context                                { return Default.With() }

//

func WithProvide(cont *di.Container) Option {
	return func(l *Logger) {
		di.MustProvide(cont, func() *Logger { return l })
	}
}

func WithInvoke(cont *di.Container, f di.Function) Option {
	return func(l *Logger) { di.MustInvoke(cont, f) }
}

func WithHook(h Hook) Option {
	return func(l *Logger) {
		l.Hook(h)
	}
}

//

func (e *EventDecoratorError) Error() string { return e.Err.Error() }
func (e *EventDecoratorError) DecorateEvent(evt *Event) {
	for k, v := range e.Meta {
		evt.Interface(k, v)
	}
}

func NewEventDecoratorError(err error, meta map[string]interface{}) *EventDecoratorError {
	return &EventDecoratorError{
		Err:  err,
		Meta: meta,
	}
}

func Decorate(e *Event, v interface{}) *Event {
	switch ec := v.(type) {
	case EventDecorator:
		ec.DecorateEvent(e)
	}
	return e
}

//

func New(level string, options ...Option) (Logger, error) {
	var (
		output = os.Stdout

		log      Logger
		logLevel Level
		err      error
		w        io.Writer
	)

	if console.IsTerminal(output.Fd()) {
		w = zerolog.ConsoleWriter{Out: output}
	} else {
		w = output
	}

	if level == "" {
		level = LevelInfo.String()
	}
	logLevel, err = zerolog.ParseLevel(level)
	if err != nil {
		return log, errors.Wrapf(err, "failed to parse logging level %q", level)
	}

	log = zerolog.New(w).With().
		Timestamp().Stack().Logger().
		Level(logLevel)

	for _, option := range options {
		option(&log)
	}

	return log, nil
}

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
}

func Init(level string, options ...Option) error {
	l, err := New(level, options...)
	if err != nil {
		return err
	}

	Default = l

	return nil
}
