//go:build windows

package outokens

import "os"

func platformSignals() []os.Signal {
	// Windows doesn't have SIGTERM/SIGUSR1 in syscall; os.Interrupt works.
	return []os.Signal{os.Interrupt}
}
