package helperwire

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSharedFrameFixtures(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "protocol", "v1", "fixtures", "frames.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID, Expect string
		Parts      []struct {
			Text, Hex string
			Repeat    int
		}
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			var raw []byte
			for _, part := range tc.Parts {
				encoded := []byte(part.Text)
				if part.Hex != "" {
					encoded, err = hex.DecodeString(part.Hex)
					if err != nil {
						t.Fatal(err)
					}
				}
				raw = append(raw, bytes.Repeat(encoded, max(1, part.Repeat))...)
			}
			_, err := ReadFrame(bufio.NewReader(bytes.NewReader(raw)))
			got := "accepted"
			switch err {
			case nil:
			case io.EOF:
				got = "clean_eof"
			default:
				got = err.Error()
			}
			if got != tc.Expect {
				t.Fatalf("frame outcome %q, want %q", got, tc.Expect)
			}
		})
	}
}
