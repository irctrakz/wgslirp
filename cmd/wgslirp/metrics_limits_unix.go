//go:build unix

package main

import "syscall"

func fileDescriptorLimits() (soft, hard uint64, available bool) {
	var limits syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limits); err != nil {
		return 0, 0, false
	}
	return limits.Cur, limits.Max, true
}
