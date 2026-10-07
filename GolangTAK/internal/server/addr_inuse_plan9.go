//go:build plan9

package server

import "errors"

var errAddrInUse = errors.New("address already in use")
