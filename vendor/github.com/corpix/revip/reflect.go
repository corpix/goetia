package revip

import (
	"reflect"

	"github.com/pkg/errors"
)

func indirectValue(reflectValue reflect.Value) reflect.Value {
	if reflectValue.Kind() == reflect.Ptr {
		return reflectValue.Elem()
	}
	return reflectValue
}

func indirectType(reflectType reflect.Type) reflect.Type {
	if reflectType.Kind() == reflect.Ptr || reflectType.Kind() == reflect.Slice {
		return reflectType.Elem()
	}
	return reflectType
}

func isNil(reflectValue reflect.Value) bool {
	if reflectValue.Kind() == reflect.Ptr {
		return reflectValue.IsNil()
	}
	return false
}

func expectKind(reflectType reflect.Type, ks ...reflect.Kind) error {
	k := reflectType.Kind()

	for _, ek := range ks {
		if ek == k {
			return nil
		}
	}

	return errors.WithStack(&ErrUnexpectedKind{
		Type:     reflectType,
		Got:      k,
		Expected: ks,
	})
}
