package log

type StdLogger struct{ Logger }

func (l StdLogger) Printf(format string, v ...interface{}) { l.Logger.Printf(format, v...) }
func (l StdLogger) Print(v ...interface{})                 { l.Logger.Print(v...) }
func (l StdLogger) Println(v ...interface{})               { l.Logger.Print(v...) }

func (l StdLogger) Debug(v ...interface{})                 { l.Logger.Debug().Msgf("%v", v) }
func (l StdLogger) Debugf(format string, v ...interface{}) { l.Logger.Debug().Msgf(format, v...) }
func (l StdLogger) Error(v ...interface{})                 { l.Logger.Error().Msgf("%v", v) }
func (l StdLogger) Errorf(format string, v ...interface{}) { l.Logger.Error().Msgf(format, v...) }
func (l StdLogger) Fatal(v ...interface{})                 { l.Logger.Fatal().Msgf("%v", v) }
func (l StdLogger) Fatalf(format string, v ...interface{}) { l.Logger.Fatal().Msgf(format, v...) }
func (l StdLogger) Fatalln(v ...interface{})               { l.Logger.Fatal().Msgf("%v", v) }
func (l StdLogger) Panic(v ...interface{})                 { l.Logger.Panic().Msgf("%v", v) }
func (l StdLogger) Panicf(format string, v ...interface{}) { l.Logger.Panic().Msgf(format, v...) }
func (l StdLogger) Panicln(v ...interface{})               { l.Logger.Panic().Msgf("%v", v) }

//

func Std(l Logger) StdLogger { return StdLogger{l} }
