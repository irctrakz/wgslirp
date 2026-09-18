// Package envconfig decodes startup environment snapshots without reading global state.
package envconfig

import (
	"fmt"
	"strconv"
	"strings"
)

type Reader struct {
	Lookup func(string) (string, bool)
	Err    error
}

func (r *Reader) Invalid(name, requirement string) {
	if r.Err == nil {
		r.Err = fmt.Errorf("%s %s", name, requirement)
	}
}

func (r *Reader) Text(name, fallback string) string {
	if v, ok := r.Lookup(name); ok {
		return strings.TrimSpace(v)
	}
	return fallback
}

func (r *Reader) Int(name string, fallback, min, max int) int {
	v, ok := r.Lookup(name)
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < min || n > max {
		r.Invalid(name, fmt.Sprintf("must be an integer between %d and %d", min, max))
		return fallback
	}
	return n
}

func (r *Reader) Bool(name string, fallback bool) bool {
	v, ok := r.Lookup(name)
	if !ok {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		r.Invalid(name, "must be a boolean (true/false, 1/0, yes/no or on/off)")
		return fallback
	}
}
