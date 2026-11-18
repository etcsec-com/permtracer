//go:build !windows

package main

import (
	"errors"

	"github.com/etcsec-com/permtracer/internal/saas"
)

func isWindowsServiceContext() bool {
	return false
}

func runDaemonAsWindowsService(_ *saas.Daemon) error {
	return errors.New("Windows service not supported on this platform")
}
