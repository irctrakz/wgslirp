package main

import (
	"testing"
	"time"
)

func TestMetricsInterval(t *testing.T) {
	for _, value := range []string{"0s", "-1s", "broken"} {
		if _, err := metricsInterval(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	if d, err := metricsInterval(""); err != nil || d != 30*time.Second {
		t.Fatalf("default: %v %v", d, err)
	}
}
