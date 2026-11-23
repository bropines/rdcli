//go:build windows

package term

import (
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func openTTY() (in, out *os.File, err error) {
	f, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	g, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, g, nil
}

// enableVT turns on ANSI escape processing for a console output handle and
// returns a function that restores the previous mode.
func enableVT(f *os.File) func() {
	h := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return func() {}
	}
	if windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.DISABLE_NEWLINE_AUTO_RETURN) != nil {
		windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
	return func() { windows.SetConsoleMode(h, mode) }
}

// watchResize polls: Windows consoles have no SIGWINCH.
func watchResize(fn func()) (stop func()) {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(300 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				fn()
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}
