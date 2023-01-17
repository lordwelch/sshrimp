//go:build darwin || linux
// +build darwin linux

package main

import (
	"syscall"
)

func init() {
	sigExit = append(sigExit, syscall.SIGTERM)
	sigIgnore = append(sigIgnore, syscall.SIGHUP)
}
