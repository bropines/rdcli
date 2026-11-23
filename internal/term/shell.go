// Package term runs RustDesk's remote terminal in the local console and
// asks for secrets on the controlling terminal.
package term

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	xterm "golang.org/x/term"

	"github.com/bropines/rdcli/internal/pb"
	"github.com/bropines/rdcli/internal/peer"
)

const (
	firstTerminal = 0
	maxChunk      = 4 << 20
	openTimeout   = 20 * time.Second
)

// ShellOptions configures RunShell.
type ShellOptions struct {
	// Persistent asks the device to keep the shell running when the link
	// drops, for a later reattach with the printed service id.
	Persistent bool
	// ServiceID reattaches to an earlier persistent shell.
	ServiceID string
	// Escape is the escape character at the start of a line (default '~';
	// -1 disables): "~." disconnects, "~~" sends one "~", "~?" lists them.
	Escape int
	// Command is run in the shell, which then exits. On POSIX peers only its
	// output is printed and its exit status returned (see WrapCommand).
	Command string
	// RawCommand types Command as is, followed by exit: the output then
	// includes the prompts and the shell's echo (Windows peers always).
	RawCommand bool
}

// LoginFields returns the LoginRequest fields of a terminal session.
func LoginFields(o ShellOptions, osUser, osPassword string) func(*pb.LoginRequest) {
	return func(lr *pb.LoginRequest) {
		if o.Persistent {
			lr.Option = &pb.OptionMessage{TerminalPersistent: pb.OptionMessage_Yes}
		}
		if osUser != "" {
			lr.OsLogin = &pb.OSLogin{Username: osUser, Password: osPassword}
		}
		lr.Union = &pb.LoginRequest_Terminal{Terminal: &pb.Terminal{ServiceId: o.ServiceID}}
	}
}

// LoginErrorCode classifies a terminal login refusal.
func LoginErrorCode(e string) peer.Code {
	l := strings.ToLower(e)
	switch {
	case strings.Contains(l, "no permission") || strings.Contains(l, "not allowed") || strings.Contains(l, "disabled"):
		return peer.CodePermissionDenied
	default:
		return peer.CodeLogin
	}
}

type event struct {
	data   []byte
	exit   *int
	err    error
	opened *pb.TerminalOpened
}

// Result describes how a shell ended.
type Result struct {
	ExitCode int
	// ServiceID of a persistent shell left running (detached).
	ServiceID string
	Detached  bool
}

// RunShell opens terminal 0 on a logged-in session and connects it to the
// local console until the remote shell exits or the user disconnects.
func RunShell(ctx context.Context, s *peer.Session, o ShellOptions) (Result, error) {
	if o.Escape == 0 {
		o.Escape = '~'
	}
	stdinTTY := IsTerminal(os.Stdin)
	stdoutTTY := IsTerminal(os.Stdout)
	cols, rows := 80, 24
	if stdoutTTY {
		if w, h, err := xterm.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 && h > 0 {
			cols, rows = w, h
		}
	}

	events := make(chan event, 64)
	var once sync.Once
	stopReader := make(chan struct{})
	go readLoop(s, events, stopReader)
	defer once.Do(func() { close(stopReader) })

	kctx, kcancel := context.WithCancel(ctx)
	defer kcancel()
	go s.KeepAlive(kctx, 20*time.Second)

	send := func(a *pb.TerminalAction) error {
		return s.Send(&pb.Message{Union: &pb.Message_TerminalAction{TerminalAction: a}})
	}
	if err := send(&pb.TerminalAction{Union: &pb.TerminalAction_Open{Open: &pb.OpenTerminal{
		TerminalId: firstTerminal, Rows: uint32(rows), Cols: uint32(cols),
	}}}); err != nil {
		return Result{}, err
	}

	// Wait for the shell to open; output may arrive in the same burst.
	var serviceID string
	timer := time.NewTimer(openTimeout)
	var early [][]byte
wait:
	for {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-timer.C:
			return Result{}, errors.New("the device did not open a terminal")
		case ev := <-events:
			switch {
			case ev.err != nil:
				return Result{}, ev.err
			case ev.opened != nil:
				if !ev.opened.GetSuccess() {
					msg := ev.opened.GetMessage()
					if msg == "" {
						msg = "the device could not open a terminal"
					}
					return Result{}, errors.New(msg)
				}
				serviceID = ev.opened.GetServiceId()
				break wait
			case ev.data != nil:
				early = append(early, ev.data)
			case ev.exit != nil:
				return Result{ExitCode: *ev.exit}, nil
			}
		}
	}
	timer.Stop()

	if stdoutTTY {
		restore := enableVT(os.Stdout)
		defer restore()
	}
	if stdinTTY {
		old, err := xterm.MakeRaw(int(os.Stdin.Fd()))
		if err == nil {
			defer xterm.Restore(int(os.Stdin.Fd()), old)
		}
		stop := watchResize(func() {
			w, h, err := xterm.GetSize(int(os.Stdout.Fd()))
			if err != nil || w <= 0 || h <= 0 || (w == cols && h == rows) {
				return
			}
			cols, rows = w, h
			send(&pb.TerminalAction{Union: &pb.TerminalAction_Resize{Resize: &pb.ResizeTerminal{
				TerminalId: firstTerminal, Rows: uint32(h), Cols: uint32(w),
			}}})
		})
		defer stop()
	}
	var filter *cmdFilter
	if o.Command != "" && !o.RawCommand && !isWindowsPeer(s) {
		filter = &cmdFilter{crlf: !stdoutTTY}
	}
	// show writes terminal output; done: the wrapped command finished.
	show := func(d []byte) (done bool, code int) {
		if filter == nil {
			os.Stdout.Write(d)
			return false, 0
		}
		out, done, code := filter.feed(d)
		os.Stdout.Write(out)
		return done, code
	}
	for _, d := range early {
		if done, code := show(d); done {
			s.Close("")
			return Result{ExitCode: code}, nil
		}
	}

	writeData := func(b []byte) error {
		for len(b) > 0 {
			n := min(len(b), 32<<10)
			if err := send(&pb.TerminalAction{Union: &pb.TerminalAction_Data{Data: &pb.TerminalData{
				TerminalId: firstTerminal, Data: append([]byte(nil), b[:n]...),
			}}}); err != nil {
				return err
			}
			b = b[n:]
		}
		return nil
	}
	if filter != nil {
		writeData([]byte(WrapCommand(o.Command)))
	} else if o.Command != "" {
		eol := "\n"
		if isWindowsPeer(s) {
			// Enter is CR; PSReadLine takes LF (Ctrl+J) for "add a line",
			// which leaves the exit stuck at a continuation prompt.
			eol = "\r"
		}
		writeData([]byte(o.Command + eol + "exit" + eol))
	}

	input := make(chan []byte, 16)
	inputErr := make(chan error, 1)
	if o.Command == "" {
		go readInput(os.Stdin, input, inputErr)
	}
	winPeer := isWindowsPeer(s)
	var lf lineEnds
	esc := &escaper{char: o.Escape, lineStart: true, enabled: stdinTTY && o.Escape > 0}

	detach := func() (Result, error) {
		if o.Persistent || o.ServiceID != "" {
			s.Close("detached")
			return Result{ServiceID: serviceID, Detached: true}, nil
		}
		send(&pb.TerminalAction{Union: &pb.TerminalAction_Close{Close: &pb.CloseTerminal{TerminalId: firstTerminal}}})
		s.Close("closed by user")
		return Result{ExitCode: 255, Detached: true}, nil
	}

	for {
		select {
		case <-ctx.Done():
			return detach()
		case ev := <-events:
			switch {
			case ev.err != nil:
				if errors.Is(ev.err, io.EOF) {
					// closed without reporting the shell's exit
					return Result{ServiceID: serviceID}, errors.New("the device closed the connection")
				}
				return Result{ServiceID: serviceID}, ev.err
			case ev.data != nil:
				if done, code := show(ev.data); done {
					s.Close("")
					return Result{ExitCode: code}, nil
				}
			case ev.exit != nil:
				s.Close("")
				if filter != nil && !filter.started {
					return Result{ExitCode: *ev.exit}, errors.New("the shell on the device ended without running the command (not a POSIX shell? try --raw)")
				}
				return Result{ExitCode: *ev.exit}, nil
			}
		case b := <-input:
			if !stdinTTY && winPeer {
				b = lf.toCR(b)
			}
			out, action := esc.feed(b)
			if len(out) > 0 {
				if err := writeData(out); err != nil {
					return Result{}, err
				}
			}
			switch action {
			case escDisconnect:
				os.Stderr.WriteString("\r\n[rdcli: disconnected]\r\n")
				return detach()
			case escHelp:
				os.Stderr.WriteString("\r\nSupported escape sequences:\r\n ~.  disconnect\r\n ~~  send ~\r\n ~?  this help\r\n")
			}
		case err := <-inputErr:
			input = nil
			inputErr = nil
			if err == io.EOF && !stdinTTY && isWindowsPeer(s) {
				writeData([]byte("\rexit\r")) // cmd/PowerShell have no ^D; Enter is CR
			} else if err == io.EOF && !stdinTTY {
				writeData([]byte{4}) // ^D: end of input for the remote shell
			}
		}
	}
}

// lineEnds turns piped line ends into the Enter (CR) a Windows console
// expects: LF and CRLF become CR, also across reads.
type lineEnds struct{ lastCR bool }

func (l *lineEnds) toCR(in []byte) []byte {
	out := make([]byte, 0, len(in))
	for _, c := range in {
		switch {
		case c == '\n' && l.lastCR:
		case c == '\n':
			out = append(out, '\r')
		default:
			out = append(out, c)
		}
		l.lastCR = c == '\r'
	}
	return out
}

func isWindowsPeer(s *peer.Session) bool {
	return s.PeerInfo != nil && strings.Contains(strings.ToLower(s.PeerInfo.GetPlatform()), "windows")
}

func readInput(r io.Reader, out chan<- []byte, errc chan<- error) {
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out <- append([]byte(nil), buf[:n]...)
		}
		if err != nil {
			errc <- err
			return
		}
	}
}

func readLoop(s *peer.Session, events chan<- event, stop <-chan struct{}) {
	dec, _ := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxChunk), zstd.WithDecoderConcurrency(1))
	defer dec.Close()
	emit := func(ev event) bool {
		select {
		case events <- ev:
			return true
		case <-stop:
			return false
		}
	}
	for {
		m, err := s.Recv()
		if err != nil {
			emit(event{err: err})
			return
		}
		tr, ok := m.Union.(*pb.Message_TerminalResponse)
		if !ok {
			continue
		}
		switch u := tr.TerminalResponse.Union.(type) {
		case *pb.TerminalResponse_Opened:
			if u.Opened.GetTerminalId() == firstTerminal && !emit(event{opened: u.Opened}) {
				return
			}
		case *pb.TerminalResponse_Data:
			if u.Data.GetTerminalId() != firstTerminal {
				continue
			}
			data := u.Data.GetData()
			if u.Data.GetCompressed() {
				out, err := dec.DecodeAll(data, nil)
				if err != nil || len(out) > maxChunk {
					continue
				}
				data = out
			}
			if len(data) > 0 && !emit(event{data: data}) {
				return
			}
		case *pb.TerminalResponse_Closed:
			if u.Closed.GetTerminalId() == firstTerminal {
				code := int(u.Closed.GetExitCode())
				emit(event{exit: &code})
				return
			}
		case *pb.TerminalResponse_Error:
			msg := fmt.Sprintf("\r\n[%s]\r\n", u.Error.GetMessage())
			if !emit(event{data: []byte(msg)}) {
				return
			}
		}
	}
}

type escAction int

const (
	escNone escAction = iota
	escDisconnect
	escHelp
)

// escaper implements ssh-style escapes typed at the start of a line.
type escaper struct {
	char      int
	enabled   bool
	lineStart bool
	pending   bool
}

func (e *escaper) feed(in []byte) ([]byte, escAction) {
	if !e.enabled {
		return in, escNone
	}
	var out bytes.Buffer
	for _, c := range in {
		if e.pending {
			e.pending = false
			switch c {
			case '.':
				return out.Bytes(), escDisconnect
			case '?':
				return out.Bytes(), escHelp
			case byte(e.char):
				out.WriteByte(c)
				e.lineStart = false
				continue
			default:
				out.WriteByte(byte(e.char))
			}
		} else if e.lineStart && int(c) == e.char {
			e.pending = true
			continue
		}
		out.WriteByte(c)
		e.lineStart = c == '\r' || c == '\n'
	}
	return out.Bytes(), escNone
}
