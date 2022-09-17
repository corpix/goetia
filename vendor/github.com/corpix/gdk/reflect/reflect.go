package reflect

import (
	"fmt"
	"reflect"
	"sort"
)

type (
	Type        = reflect.Type
	Kind        = reflect.Kind
	Value       = reflect.Value
	StructField = reflect.StructField
)

const (
	Invalid       = reflect.Invalid
	Bool          = reflect.Bool
	Int           = reflect.Int
	Int8          = reflect.Int8
	Int16         = reflect.Int16
	Int32         = reflect.Int32
	Int64         = reflect.Int64
	Uint          = reflect.Uint
	Uint8         = reflect.Uint8
	Uint16        = reflect.Uint16
	Uint32        = reflect.Uint32
	Uint64        = reflect.Uint64
	Uintptr       = reflect.Uintptr
	Float32       = reflect.Float32
	Float64       = reflect.Float64
	Complex64     = reflect.Complex64
	Complex128    = reflect.Complex128
	Array         = reflect.Array
	Chan          = reflect.Chan
	Func          = reflect.Func
	Interface     = reflect.Interface
	Map           = reflect.Map
	Ptr           = reflect.Ptr
	Slice         = reflect.Slice
	String        = reflect.String
	Struct        = reflect.Struct
	UnsafePointer = reflect.UnsafePointer
)

var (
	TypeOf  = reflect.TypeOf
	ValueOf = reflect.ValueOf
)

func IndirectValue(reflectValue reflect.Value) reflect.Value {
	if reflectValue.Kind() == reflect.Ptr {
		return reflectValue.Elem()
	}
	return reflectValue
}

func IndirectType(reflectType reflect.Type) reflect.Type {
	if reflectType.Kind() == reflect.Ptr || reflectType.Kind() == reflect.Slice {
		return reflectType.Elem()
	}
	return reflectType
}

func ExpectKind(reflectType reflect.Type, ks ...reflect.Kind) error {
	k := reflectType.Kind()

	for _, ek := range ks {
		if ek == k {
			return nil
		}
	}

	return &ErrUnexpectedKind{
		Got:      k,
		Expected: ks,
	}
}

func IsNil(reflectValue reflect.Value) bool {
	switch reflectValue.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice:
		return reflectValue.IsNil()
	default:
		return false
	}
}

func MapKeys(v reflect.Value) []string {
	err := ExpectKind(v.Type(), reflect.Map)
	if err != nil {
		panic(err)
	}

	rawKeys := v.MapKeys()
	keys := make([]string, len(rawKeys))
	n := 0
	for _, key := range rawKeys {
		keys[n] = fmt.Sprintf("%v", key.Interface())
		n++
	}
	return keys
}

func MapSortedKeys(v reflect.Value) []string {
	keys := MapKeys(v)
	sort.Strings(keys)
	return keys
}
