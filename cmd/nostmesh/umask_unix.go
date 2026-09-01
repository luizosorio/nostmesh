//go:build unix

package main

import "syscall"

// setUmask sets the process umask and returns the previous value.
//
// It exists for a test that has to create a socket under a permissive umask, to
// confirm the service narrows it afterwards rather than trusting the default.
func setUmask(mask int) int { return syscall.Umask(mask) }
