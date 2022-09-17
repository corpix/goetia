package revip

import (
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"reflect"
	"syscall"

	json "encoding/json"

	yaml "gopkg.in/yaml.v2"
	env "github.com/kelseyhightower/envconfig"
	toml "github.com/pelletier/go-toml"
)

type SourceOption func(c Config) error

// Unmarshaler describes a generic unmarshal interface for data decoding
// which could be used to extend supported formats by defining new `SourceOption`
// implementations.
type Unmarshaler = func(in []byte, v interface{}) error

var (
	JsonUnmarshaler Unmarshaler = json.Unmarshal
	YamlUnmarshaler Unmarshaler = yaml.Unmarshal
	TomlUnmarshaler Unmarshaler = toml.Unmarshal
)

// FromReader is an `SourceOption` constructor which creates a thunk
// to read configuration from `r` and decode it with `f` unmarshaler.
// Current implementation buffers all data in memory.
func FromReader(r io.Reader, f Unmarshaler) SourceOption {
	return func(c Config) error {
		err := expectKind(reflect.TypeOf(c), reflect.Ptr)
		if err != nil {
			return err
		}

		buf, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}

		return f(buf, c)
	}
}

// FromFile is an `SourceOption` constructor which creates a thunk
// to read configuration from file addressable by `path` with
// content decoded with `f` unmarshaler.
func FromFile(path string, f Unmarshaler) SourceOption {
	return func(c Config) error {
		err := expectKind(reflect.TypeOf(c), reflect.Ptr)
		if err != nil {
			return err
		}

		r, err := os.Open(path)
		switch e := err.(type) {
		case *os.PathError:
			if e.Err == syscall.ENOENT {
				return &ErrFileNotFound{
					Path: path,
					Err:  err,
				}
			}
		case nil:
		default:
			return err
		}
		defer r.Close()

		return FromReader(r, f)(c)
	}
}

// FromEnviron is an `SourceOption` constructor which creates a thunk
// to read configuration from environment.
// It uses `github.com/kelseyhightower/envconfig` underneath.
func FromEnviron(prefix string) SourceOption {
	return func(c Config) error {
		err := expectKind(reflect.TypeOf(c), reflect.Ptr)
		if err != nil {
			return err
		}

		return env.Process(prefix, c)
	}
}

//

// FromURL creates a source from URL.
// Example URL's:
//   - file://./config.yml
//   - env://prefix
func FromURL(u string, d Unmarshaler) (SourceOption, error) {
	uu, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	switch uu.Scheme {
	case SchemeFile, SchemeEmpty:
		return FromFile(path.Join(uu.Host, uu.Path), d), nil
	case SchemeEnviron:
		return FromEnviron(uu.Host), nil
	default:
		return nil, &ErrUnexpectedScheme{
			Got:      uu.Scheme,
			Expected: FromSchemes,
		}
	}
}
