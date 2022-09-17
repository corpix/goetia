# revip

Dead-simple configuration loader.

It supports:

- JSON, TOML, YAML and you could add your own format unmarshaler (see `Unmarshaler` type)
- file, reader and environment sources support, also you could add your own (see `Option` type and `sources.go`)
- extendable postprocessing support (defaults, validation, expansion, see `Option` type and `postprocess.go`)
- dot-notation to access configuration keys

[Godoc](https://godoc.org/github.com/corpix/revip)

---

### example


### run

Basic example showing basics about configuration loading:

- default values
- validation rules
- config expansion (loading `key` from file)
- working with nested types
- unmarshaling from JSON, YAML, TOML

```console
$ cd ./example/basic
$ go run ./main.go
(main.Config) {
 SerialNumber: (int) 1,
 Nested: (*main.NestedConfig)(0xc00000e0c0)({
  Value: (string) (len=11) "hello world",
  Flag: (bool) false
 }),
 MapNested: (map[string]*main.NestedConfig) {
 },
 SliceNested: ([]*main.NestedConfig) {
 },
 StringSlice: ([]string) <nil>,
 IntSlice: ([]int) (len=3 cap=3) {
  (int) 666,
  (int) 777,
  (int) 888
 },
 key: (string) (len=18) "super secret value"
}
```

Run basic example with some keys befined through environment variables:

> environment variables are defined in `makefile`

```console
$ make
(main.Config) {
 SerialNumber: (int) 2,
 Nested: (*main.NestedConfig)(0xc00000e0c0)({
  Value: (string) (len=12) "\"hello user\"",
  Flag: (bool) false
 }),
 MapNested: (map[string]*main.NestedConfig) {
 },
 SliceNested: ([]*main.NestedConfig) {
 },
 StringSlice: ([]string) <nil>,
 IntSlice: ([]int) (len=3 cap=3) {
  (int) 888,
  (int) 777,
  (int) 666
 },
 key: (string) (len=18) "super secret value"
}
```

## license

[public domain](https://unlicense.org/)
