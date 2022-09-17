package revip

import (
	"fmt"
	"reflect"
)

// ErrFileNotFound should be returned if configuration file was not found.
type ErrFileNotFound struct {
	Path string
	Err  error
}

func (e *ErrFileNotFound) Error() string {
	return fmt.Sprintf("no such file: %q", e.Path)
}

//

// ErrPathNotFound should be returned if key (path) was not found in configuration.
type ErrPathNotFound struct {
	Path string
}

func (e *ErrPathNotFound) Error() string {
	return fmt.Sprintf("no key matched for path: %q", e.Path)
}

//

// ErrMarshal should be returned if key marshaling failed.
type ErrMarshal struct {
	At  string
	Err error
}

func (e *ErrMarshal) Error() string {
	return fmt.Sprintf("failed to marshal at: %q: %s", e.At, e.Err)
}

//

// ErrUnmarshal should be returned if key unmarshaling failed.
type ErrUnmarshal struct {
	At  string
	Err error
}

func (e *ErrUnmarshal) Error() string {
	return fmt.Sprintf("failed to unmarshal at: %q: %s", e.At, e.Err)
}

//

// ErrPostprocess represents an error occured at the postprocess stage (set defaults, validation, etc)
type ErrPostprocess struct {
	Path string
	Err  error
}

func (e *ErrPostprocess) Error() string {
	return fmt.Sprintf(
		"postprocessing failed at %s: %s",
		e.Path,
		e.Err.Error(),
	)
}

//

// ErrUnexpectedKind represents an unexpected interface{} value kind received by some function.
// For example passing non pointer value to a function which expects pointer (like json.Unmarshal)
type ErrUnexpectedKind struct {
	Type     reflect.Type
	Got      reflect.Kind
	Expected []reflect.Kind
}

func (e *ErrUnexpectedKind) Error() string {
	var expected string
	if len(e.Expected) > 1 {
		expected = fmt.Sprintf("one of %q", e.Expected)
	} else {
		expected = fmt.Sprintf("%q", e.Expected[0])
	}
	return fmt.Sprintf(
		"unexpected kind %s for type %s, expected "+expected,
		e.Got,
		e.Type,
	)
}

//

// ErrUnexpectedScheme represents an unexpected URL scheme.
type ErrUnexpectedScheme struct {
	Got      string
	Expected []string
}

func (e *ErrUnexpectedScheme) Error() string {
	return fmt.Sprintf(
		"unexpected scheme %s, expected one of %s",
		e.Got,
		e.Expected,
	)
}
