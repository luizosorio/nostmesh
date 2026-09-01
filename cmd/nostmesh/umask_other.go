//go:build !unix

package main

// setUmask is a no-op where the concept does not exist. The permission check it
// supports is meaningful only on systems with one.
func setUmask(int) int { return 0 }
