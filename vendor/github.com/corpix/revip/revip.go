package revip

import (
	"reflect"

	"github.com/mitchellh/mapstructure"
)

const (
	SchemeEmpty   = ""
	SchemeFile    = "file" // file://./config.yml
	SchemeEnviron = "env"  // env://prefix
)

var (
	// FromSchemes represents schemes supported for sources.
	FromSchemes = []string{
		SchemeFile,
		SchemeEnviron,
	}
	// ToSchemes represents schemes supported for destrinations.
	ToSchemes = []string{
		SchemeFile,
	}
)

// Config is a configuration represented by user-specified type.
type Config interface{}

// Defaultable is an interface which any `Config` could implement
// to define a custom default values for sub-tree it owns.
type Defaultable interface {
	Default()
}

// Validatable is an interface which any `Config` could implement
// to define a validation rules for sub-tree it owns.
type Validatable interface {
	Validate() error
}

// Expandable is an interface which any `Config` could implement
// to define an expansion rules for sub-tree it owns.
type Expandable interface {
	Expand() error
}

// Container represents configuration loaded by `Load`.
type Container struct {
	// config represents configuration data, it should always be a pointer.
	config Config
	index  map[string]Tree
}

// Unwrap returns a pointer to the inner configuration data structure.
func (r *Container) Unwrap() Config { return r.config }

// EmptyClone returns empty configuration type clone.
func (r *Container) EmptyClone() Config {
	t := indirectType(reflect.TypeOf(r.config))
	return reflect.New(t).Interface()
}

// Empty allocates a new empty configuration, discarding any previously loaded data.
func (r *Container) Empty() {
	cfg := r.EmptyClone()
	r.config = cfg
}

// Replace overrides internally stored configuration with passed value.
func (r *Container) Replace(c Config) {
	r.config = c
}

// Copy writes a shallow copy of the configuration into `v`.
func (r *Container) Copy(v Config) error {
	return mapstructure.WeakDecode(r.config, v)
}

// Clone returns a shallow copy of the configuration with the same type.
func (r *Container) Clone() (Config, error) {
	v := r.EmptyClone()
	err := r.Copy(v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// DeepCopy writes a deep copy of the configuration into `v`.
func (r *Container) DeepCopy(v Config) error {
	return mapstructure.Decode(r.config, v)
}

// DeepClone returns a deep copy of the configuration with the same type.
func (r *Container) DeepClone() (Config, error) {
	v := r.EmptyClone()
	err := r.DeepCopy(v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// Path uses dot notation to retrieve substruct addressable by `path` or
// return an error if key was not found(`ErrNotFound`) or
// something gone terribly wrong.
func (r *Container) Path(path string) (Config, error) {
	if r.index == nil {
		r.index = map[string]Tree{}
		_, _ = NewTree(reflect.ValueOf(r.config), func(t Tree) error {
			r.index[TreePathString(t)] = t
			return nil
		})
	}
	v, ok := r.index[path]
	if !ok {
		return nil, &ErrPathNotFound{Path: path}
	}

	return v, nil
}

// Default postprocess configuration with default values or returns an error.
func (r *Container) Default() error {
	return Postprocess(r.config, WithDefaults())
}

// Validate postprocess configuration with validation or returns an error.
func (r *Container) Validate() error {
	return Postprocess(r.config, WithValidation())
}

// Expand postprocess configuration with expansion or returns an error.
func (r *Container) Expand() error {
	return Postprocess(r.config, WithExpansion())
}

// New wraps configuration represented by `c` with come useful methods.
func New(c Config) *Container {
	if reflect.TypeOf(c).Kind() != reflect.Ptr {
		panic("config must be a pointer")
	}

	return &Container{config: c}
}

// Load applies each `options` in order to fill the configuration in `v` and
// constructs a `*Revip` data-structure.
func Load(v Config, options ...SourceOption) (*Container, error) {
	var err error
	for _, f := range options {
		err = f(v)
		if err != nil {
			return nil, err
		}
	}

	return New(v), nil
}
