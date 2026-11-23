package term

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	xterm "golang.org/x/term"
)

// ErrNoTTY means a secret is needed but there is no terminal to ask on.
var ErrNoTTY = errors.New("no terminal to ask for it (use --password-stdin, RDCLI_PASSWORD or --approval)")

// Prompter asks on the controlling terminal, not stdin, so it works while
// stdin carries data (rdcli pipe as an ssh ProxyCommand).
type Prompter struct {
	PeerID string
	// Quiet suppresses status lines.
	Quiet bool
	// NoRetry: refuse instead of asking again after a wrong password.
	NoRetry bool
	mu      sync.Mutex
}

// CanRetry implements peer's retry hint.
func (p *Prompter) CanRetry() bool { return !p.NoRetry }

func (p *Prompter) Password(wrong bool) (string, error) {
	label := fmt.Sprintf("Password for %s: ", p.PeerID)
	if wrong {
		label = fmt.Sprintf("Wrong password. Password for %s: ", p.PeerID)
	}
	return p.readSecret(label)
}

func (p *Prompter) TwoFactor(wrong bool) (string, error) {
	label := "2FA code: "
	if wrong {
		label = "Wrong code. 2FA code: "
	}
	return p.readLine(label)
}

func (p *Prompter) Status(msg string) {
	if p.Quiet {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(os.Stderr, "rdcli: %s\r\n", Sanitize(msg))
}

func (p *Prompter) readSecret(label string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	in, out, err := openTTY()
	if err != nil {
		return "", ErrNoTTY
	}
	defer in.Close()
	defer out.Close()
	fmt.Fprint(out, label)
	if st, err := xterm.GetState(int(in.Fd())); err == nil {
		setActive(func() { xterm.Restore(int(in.Fd()), st); fmt.Fprint(out, "\r\n") })
	} else {
		setActive(func() { fmt.Fprint(out, "\r\n") })
	}
	defer setActive(nil)
	b, err := xterm.ReadPassword(int(in.Fd()))
	fmt.Fprint(out, "\r\n")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (p *Prompter) readLine(label string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	in, out, err := openTTY()
	if err != nil {
		return "", ErrNoTTY
	}
	defer in.Close()
	defer out.Close()
	fmt.Fprint(out, label)
	setActive(func() { fmt.Fprint(out, "\r\n") })
	defer setActive(nil)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// ReadPasswordStdin reads one line from stdin (--password-stdin).
func ReadPasswordStdin() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// IsTerminal reports whether f is a terminal.
func IsTerminal(f *os.File) bool { return xterm.IsTerminal(int(f.Fd())) }

// ReadLineTTY asks a plain question on the terminal (rdcli login).
func ReadLineTTY(label string) (string, error) {
	return (&Prompter{}).readLine(label)
}

// ReadSecretTTY asks for a secret on the terminal (rdcli login).
func ReadSecretTTY(label string) (string, error) {
	return (&Prompter{}).readSecret(label)
}

var (
	activeMu sync.Mutex
	active   func()
)

func setActive(restore func()) {
	activeMu.Lock()
	active = restore
	activeMu.Unlock()
}

// InterruptPrompt restores the terminal of a prompt blocked in a read and
// reports whether there was one (a blocked read cannot see a signal).
func InterruptPrompt() bool {
	activeMu.Lock()
	defer activeMu.Unlock()
	if active == nil {
		return false
	}
	active()
	active = nil
	return true
}

// Sanitize drops control characters (escape sequences included) from text a
// server or peer sent, before it reaches the terminal.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}
