package errors

import (
	"fmt"
	"os"

	"github.com/cockroachdb/errors"
)

var (
	New       = errors.New
	Errorf    = errors.Errorf
	Wrap      = errors.Wrap
	Wrapf     = errors.Wrapf
	Is        = errors.Is
	Cause     = errors.Cause
	HasType   = errors.HasType
	WithStack = errors.WithStack
)

func Fatal(err error) {
	fmt.Fprintf(os.Stderr, "fatal error: %s\n", err)
	os.Exit(1)
}
