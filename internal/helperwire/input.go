package helperwire

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

var (
	ErrInvalidFrame  = errors.New("invalid_frame")
	ErrFrameTooLarge = errors.New("frame_too_large")
)

// ReadFrame reads one bounded, strict JSON object. Only EOF at a frame boundary
// returns io.EOF. Decoder diagnostics are never returned to the caller.
func ReadFrame(r *bufio.Reader) (map[string]any, error) {
	var payload []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			switch {
			case len(payload) > MaxFrameBytes:
				return nil, ErrFrameTooLarge
			case len(payload) == 0 && err == io.EOF:
				return nil, io.EOF
			default:
				return nil, ErrInvalidFrame
			}
		}
		if b == '\n' {
			return decodeFrame(bytes.TrimSuffix(payload, []byte{'\r'}))
		}
		if len(payload) >= MaxFrameBytes && (len(payload) > MaxFrameBytes || b != '\r') {
			return nil, ErrFrameTooLarge
		}
		payload = append(payload, b)
	}
}

func decodeFrame(payload []byte) (map[string]any, error) {
	if !utf8.Valid(payload) || !pairedSurrogates(payload) {
		return nil, ErrInvalidFrame
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	value, err := readValue(decoder, 1)
	obj, ok := value.(map[string]any)
	if err != nil || !ok {
		return nil, ErrInvalidFrame
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidFrame
	}
	return obj, nil
}

func readValue(decoder *json.Decoder, depth int) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrInvalidFrame
	}
	if n, ok := token.(json.Number); ok {
		for _, digit := range n {
			if digit < '0' || digit > '9' {
				return nil, ErrInvalidFrame
			}
		}
	}
	delim, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	if depth > 16 {
		return nil, ErrInvalidFrame
	}
	switch delim {
	case '{':
		obj := make(map[string]any)
		for decoder.More() {
			name, err := decoder.Token()
			key, ok := name.(string)
			if err != nil || !ok {
				return nil, ErrInvalidFrame
			}
			if _, duplicate := obj[key]; duplicate {
				return nil, ErrInvalidFrame
			}
			obj[key], err = readValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
		}
		_, err := decoder.Token()
		return obj, err
	case '[':
		items := []any{}
		for decoder.More() {
			value, err := readValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, value)
		}
		_, err := decoder.Token()
		return items, err
	default:
		return nil, ErrInvalidFrame
	}
}

// encoding/json replaces isolated surrogate escapes. Check them before decode.
// The decoder still checks escape syntax and whether escapes occur in strings.
func pairedSurrogates(payload []byte) bool {
	for i := 0; i < len(payload); i++ {
		if payload[i] != '\\' {
			continue
		}
		i++
		if i+4 >= len(payload) || payload[i] != 'u' {
			continue
		}
		code, err := strconv.ParseUint(string(payload[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if code < 0xd800 || code > 0xdfff {
			continue
		}
		if code >= 0xdc00 || i+6 >= len(payload) || payload[i+1] != '\\' || payload[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(payload[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
