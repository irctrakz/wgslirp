//go:build !unix

package helperwire

import "os"

// NewStdoutOutput takes ownership of the inherited protocol stream.
func NewStdoutOutput() (*Output, error) { return NewOutput(os.Stdout), nil }
