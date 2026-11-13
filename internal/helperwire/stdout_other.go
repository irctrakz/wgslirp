//go:build !unix && !windows

package helperwire

import "errors"

// NewStdoutOutput takes ownership of the inherited protocol stream.
func NewStdoutOutput() (*Output, error) { return nil, errors.New("unsupported helper stdout platform") }
