package envconfig

import "strings"

// Environment is a startup snapshot. Later entries override earlier entries,
// matching the lookup used by the executable before peer discovery was added.
type Environment map[string]string

func Snapshot(entries []string) Environment {
	values := make(Environment, len(entries))
	for _, entry := range entries {
		if key, value, ok := strings.Cut(entry, "="); ok {
			values[key] = value
		}
	}
	return values
}

func (e Environment) Lookup(key string) (string, bool) {
	value, present := e[key]
	return value, present
}
