package term

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"
)

// A one-shot command (shell -c) is typed into an interactive shell on the
// device, whose line editor may rewrite it (zsh's url-quote-magic escapes
// ";" after a URL) and which echoes it among prompts. So the command goes in
// as base64 that only eval decodes, between markers its output is cut by,
// with its exit status in the end marker. POSIX shells only: Windows peers
// get the command typed as is.

const (
	markBegin = "\x1eRDCLI:B\x1e"
	markEnd   = "\x1eRDCLI:E" // followed by the exit status and \x1e
)

// wrapChunk bounds each typed line: typed before the shell's line editor
// starts, input sits in the terminal's line buffer, which drops whatever
// exceeds MAX_CANON (1024 bytes on macOS) and never sees the newline.
const wrapChunk = 600

// WrapCommand returns the lines to type for cmd: the base64 collected into
// a variable in short lines, then eval. The leading spaces keep them out of
// the history where the shell ignores such lines.
func WrapCommand(cmd string) string {
	// The command runs in a subshell of its own eval: a syntax error or a
	// zsh "no matches found" aborts only that, not the end marker and exit.
	quoted := "'" + strings.ReplaceAll(cmd, "'", `'\''`) + "'"
	script := "unset __rdcli_b\nprintf '\\036RDCLI:B\\036\\n'\n(eval " + quoted + ")\n" +
		"__rdcli_rc=$?\nprintf '\\036RDCLI:E%d\\036\\n' \"$__rdcli_rc\"\nexit \"$__rdcli_rc\"\n"
	b := base64.StdEncoding.EncodeToString([]byte(script))
	var sb strings.Builder
	sb.WriteString(" __rdcli_b=\n")
	for len(b) > 0 {
		n := min(len(b), wrapChunk)
		sb.WriteString(" __rdcli_b=${__rdcli_b}" + b[:n] + "\n")
		b = b[n:]
	}
	// macOS before 13 knows only -D.
	sb.WriteString(" eval \"$(printf %s \"$__rdcli_b\" | base64 -d 2>/dev/null || printf %s \"$__rdcli_b\" | base64 -D)\"\n")
	return sb.String()
}

// cmdFilter passes through what a wrapped command printed, nothing else.
type cmdFilter struct {
	// crlf: turn the terminal's \r\n into \n (output is not a terminal).
	crlf    bool
	started bool
	// skipNewline: the begin marker's line end is not the command's output
	skipNewline bool
	done        bool
	code        int
	buf         []byte
	cr          bool // a \r held back at the end of the last chunk
}

// feed takes terminal output and returns what to print; done reports the
// end marker, with code the command's exit status.
func (f *cmdFilter) feed(p []byte) (out []byte, done bool, code int) {
	if f.done {
		return nil, true, f.code
	}
	f.buf = append(f.buf, p...)
	if !f.started {
		i := bytes.Index(f.buf, []byte(markBegin))
		if i < 0 {
			// keep only what could be the start of the marker
			if k := len(f.buf) - (len(markBegin) - 1); k > 0 {
				f.buf = f.buf[k:]
			}
			return nil, false, 0
		}
		f.buf = f.buf[i+len(markBegin):]
		f.started = true
		f.skipNewline = true
	}
	if f.skipNewline {
		if len(f.buf) == 0 || (len(f.buf) == 1 && f.buf[0] == '\r') {
			return nil, false, 0
		}
		switch {
		case bytes.HasPrefix(f.buf, []byte("\r\n")):
			f.buf = f.buf[2:]
		case f.buf[0] == '\n':
			f.buf = f.buf[1:]
		}
		f.skipNewline = false
	}
	var o []byte
	for len(f.buf) > 0 {
		i := bytes.IndexByte(f.buf, 0x1e)
		if i < 0 {
			o = append(o, f.buf...)
			f.buf = f.buf[:0]
			break
		}
		o = append(o, f.buf[:i]...)
		f.buf = f.buf[i:]
		n := min(len(f.buf), len(markEnd))
		if !bytes.Equal(f.buf[:n], []byte(markEnd)[:n]) {
			o = append(o, f.buf[0])
			f.buf = f.buf[1:]
			continue
		}
		if n < len(markEnd) {
			break // maybe the marker, split: wait for more
		}
		j := bytes.IndexByte(f.buf[len(markEnd):], 0x1e)
		if j < 0 {
			if len(f.buf) > len(markEnd)+12 {
				o = append(o, f.buf[0]) // not a status after all
				f.buf = f.buf[1:]
				continue
			}
			break
		}
		c, err := strconv.Atoi(string(f.buf[len(markEnd) : len(markEnd)+j]))
		if err != nil {
			o = append(o, f.buf[0])
			f.buf = f.buf[1:]
			continue
		}
		f.done, f.code = true, c
		f.buf = nil
		break
	}
	return f.convert(o), f.done, f.code
}

// convert drops the \r of \r\n when the output is not a terminal; the
// marker's own line end before the end marker goes with it.
func (f *cmdFilter) convert(o []byte) []byte {
	if !f.crlf {
		return o
	}
	var b bytes.Buffer
	if f.cr {
		f.cr = false
		if len(o) == 0 || o[0] != '\n' {
			b.WriteByte('\r')
		}
	}
	for i, c := range o {
		if c == '\r' {
			if i == len(o)-1 {
				if !f.done {
					f.cr = true
				}
				continue
			}
			if o[i+1] == '\n' {
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.Bytes()
}
