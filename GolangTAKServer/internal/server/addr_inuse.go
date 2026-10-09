//go:build !plan9

package server

import "syscall"

var errAddrInUse error = syscall.EADDRINUSE
