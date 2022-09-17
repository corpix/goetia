package revip

import (
	"reflect"
)

type PostprocessOption func(c Tree) error

func Postprocess(c Config, options ...PostprocessOption) error {
	_, err := NewTree(reflect.ValueOf(c), func(t Tree) error {
		var err error
		for _, option := range options {
			err = option(t)
			if err != nil {
				if e, ok := err.(*ErrPostprocess); ok {
					e.Path = TreePathString(t)
				}
				return err
			}
		}
		return nil
	})
	return err
}

//

func WithNoNilPointers() PostprocessOption {
	return func(t Tree) error {
		v := t.Value()
		switch v.Kind() {
		case reflect.Ptr:
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
		case reflect.Slice:
			if v.IsNil() {
				v.Set(reflect.MakeSlice(v.Type(), 0, 0))
			}
		case reflect.Map:
			if v.IsNil() {
				v.Set(reflect.MakeMap(v.Type()))
			}
		default:
			return nil
		}
		return nil
	}
}

func WithDefaults() PostprocessOption {
	return func(t Tree) error {
		v := t.Value()
		dv, ok := v.Interface().(Defaultable)
		if ok && v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return nil
			}
			dv.Default()
		}
		return nil
	}
}

func WithValidation() PostprocessOption {
	return func(t Tree) error {
		var (
			err error
			v   = t.Value()
		)
		vv, ok := v.Interface().(Validatable)
		if ok && v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return nil
			}
			err = vv.Validate()
			if err != nil {
				return &ErrPostprocess{Err: err}
			}
		}
		return nil
	}
}

func WithExpansion() PostprocessOption {
	return func(t Tree) error {
		var (
			err error
			v   = t.Value()
		)
		ev, ok := v.Interface().(Expandable)
		if ok && v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return nil
			}
			err = ev.Expand()
			if err != nil {
				return &ErrPostprocess{Err: err}
			}
		}
		return nil
	}
}
