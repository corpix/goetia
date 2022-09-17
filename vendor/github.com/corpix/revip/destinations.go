package revip

import (
	"io"
	"net/url"
	"os"
	"path"
	"reflect"

	json "encoding/json"

	yaml "gopkg.in/yaml.v2"
	toml "github.com/pelletier/go-toml"
)

type DestinationOption func(c Config) error

// Marshaler describes a generic marshal interface for data encoding
// which could be used to extend supported formats by defining new `Option`
// implementations.
type Marshaler = func(v interface{}) ([]byte, error)

var (
	JsonMarshaler Marshaler = json.Marshal
	YamlMarshaler Marshaler = yaml.Marshal
	TomlMarshaler Marshaler = toml.Marshal
)

// ToWriter is an `DestinationOption` constructor which creates a thunk
// to write configuration to `r` and encode it with `f` marshaler.
func ToWriter(w io.Writer, f Marshaler) DestinationOption {
	return func(c Config) error {
		err := expectKind(reflect.TypeOf(c), reflect.Ptr)
		if err != nil {
			return err
		}

		buf, err := f(c)
		if err != nil {
			return err
		}

		_, err = w.Write(buf)
		return err
	}
}

// ToFile is an `DestinationOption` constructor which creates a thunk
// to write configuration to file addressable by `path` with
// content encoded with `f` marshaler.
func ToFile(path string, f Marshaler) DestinationOption {
	return func(c Config) error {
		err := expectKind(reflect.TypeOf(c), reflect.Ptr)
		if err != nil {
			return err
		}

		r, err := os.OpenFile(path, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0700)
		if err != nil {
			return err
		}
		defer r.Close()

		return ToWriter(r, f)(c)
	}
}

//

// ToURL creates a destination from URL.
// Example URL's:
//   - file://./config.yml
func ToURL(u string, e Marshaler) (DestinationOption, error) {
	uu, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	switch uu.Scheme {
	case SchemeFile, SchemeEmpty:
		return ToFile(path.Join(uu.Host, uu.Path), e), nil
	default:
		return nil, &ErrUnexpectedScheme{
			Got:      uu.Scheme,
			Expected: ToSchemes,
		}
	}
}
