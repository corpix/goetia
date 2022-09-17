package reflect

import (
	"fmt"
	"reflect"
)

type ErrInvalid struct {
	v interface{}
}

func (e *ErrInvalid) Error() string {
	return fmt.Sprintf(
		"Reflect reports this value is invalid '%#v'",
		e.v,
	)
}

func NewErrInvalid(v interface{}) error {
	return &ErrInvalid{v}
}

//

// ErrUnexpectedKind represents an unexpected interface{} value kind received by some function.
// For example passing non pointer value to a function which expects pointer (like json.Unmarshal)
type ErrUnexpectedKind struct {
	Got      reflect.Kind
	Expected []reflect.Kind
}

func (e *ErrUnexpectedKind) Error() string {
	return fmt.Sprintf(
		"unexpected kind %s, expected one of %s",
		e.Got, e.Expected,
	)
}

func NewErrUnexpecterKind(got reflect.Kind, expected ...reflect.Kind) *ErrUnexpectedKind {
	return &ErrUnexpectedKind{
		Got:      got,
		Expected: expected,
	}
}

//

type ErrPtrRequired struct {
	v interface{}
}

func (e *ErrPtrRequired) Error() string {
	return fmt.Sprintf(
		"A pointer to the value '%#v' is required, not the value itself",
		e.v,
	)
}

func NewErrPtrRequired(v interface{}) error {
	return &ErrPtrRequired{v}
}
