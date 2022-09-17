package reflect

import (
	"reflect"

	"github.com/corpix/gdk/errors"
)

var (
	StopIteration = errors.New("stop iteration")
	SkipBranch    = errors.New("skip branch")
)

//

func walkStructIter(v reflect.Value, path []string, cb func(reflect.Value, []string) error) error {
	var (
		t   = v.Type()
		k   = t.Kind()
		err error
	)

	if len(path) > 0 { // do not invoke cb for root struct (it is pointless)
		err = cb(v, path)
		switch err {
		case nil:
		case SkipBranch:
			return nil
		case StopIteration:
			return err
		default:
			return err
		}
	}

	switch k {
	case reflect.Ptr:
		if !v.IsNil() {
			return walkStructIter(
				IndirectValue(v),
				path, cb,
			)
		}
	case reflect.Struct:
		for n := 0; n < v.NumField(); n++ {
			ft := t.Field(n)
			if !ft.IsExported() {
				continue
			}

			fv := v.Field(n)
			next := append(path, ft.Name)

			//

			err = walkStructIter(fv, next, cb)
			switch err {
			case nil:
			case SkipBranch:
				continue
			case StopIteration:
				return err
			default:
				return err
			}
		}

		return nil
	}

	return nil
}

func WalkStruct(value interface{}, cb func(reflect.Value, []string) error) error {
	v := IndirectValue(reflect.ValueOf(value))
	err := ExpectKind(v.Type(), reflect.Struct)
	if err != nil {
		return err
	}

	err = walkStructIter(v, []string{}, cb)
	switch err {
	case nil:
	case StopIteration:
	default:
		return err
	}

	return nil
}
