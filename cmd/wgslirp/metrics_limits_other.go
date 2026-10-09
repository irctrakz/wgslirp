//go:build !unix

package main

// An unavailable Unix limit is omitted from metrics, not reported as zero.
func fileDescriptorLimits() (soft, hard uint64, available bool) {
	return 0, 0, false
}
