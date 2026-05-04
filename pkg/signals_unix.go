//go:build linux || darwin || freebsd || netbsd || openbsd

package outokens

import (
	"os"
	"syscall"
)

func platformSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1}
}
