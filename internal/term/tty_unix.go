//go:build !windows

package term

import (
	"os"
	"os/signal"
	"syscall"
)

func openTTY() (in, out *os.File, err error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	g, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, g, nil
}

// enableVT is only needed on Windows consoles.
func enableVT(*os.File) func() { return func() {} }

// watchResize calls fn whenever the terminal size may have changed.
func watchResize(fn func()) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				fn()
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
