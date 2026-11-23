package term

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// What a zsh with a fancy prompt sends back, in every possible split.
func TestCmdFilterSplits(t *testing.T) {
	stream := "\x1b]0;title\x07% \r ❯ eval \"$(printf %s cHJp | base64 -d)\"\r\n" +
		markBegin + "\r\nline 1\r\nweird \x1e byte\r\nlast\r\n" + markEnd + "3\x1e\r\n% exit\r\n"
	want := "line 1\nweird \x1e byte\nlast\n"
	for step := 1; step <= len(stream); step++ {
		f := &cmdFilter{crlf: true}
		var got strings.Builder
		done, code := false, 0
		for i := 0; i < len(stream) && !done; i += step {
			var out []byte
			out, done, code = f.feed([]byte(stream[i:min(i+step, len(stream))]))
			got.Write(out)
		}
		if !done || code != 3 || got.String() != want {
			t.Fatalf("step %d: done=%v code=%d %q", step, done, code, got.String())
		}
	}
	// a terminal gets the bytes untouched
	f := &cmdFilter{}
	out, done, _ := f.feed([]byte(stream))
	if !done || string(out) != "line 1\r\nweird \x1e byte\r\nlast\r\n" {
		t.Fatalf("%q", out)
	}
}

// The typed line in a real POSIX shell: decoded, run, status reported.
func TestWrapCommandInShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX shell")
	}
	if _, err := exec.LookPath("base64"); err != nil {
		t.Skip("no base64")
	}
	// long enough to be typed in several lines
	pad := strings.Repeat("x", 3*wrapChunk)
	cmd := `echo "a; b" https://x.example/?q=1; : ` + pad + `; printf 'no newline'; false`
	typed := WrapCommand(cmd)
	for _, l := range strings.Split(typed, "\n") {
		if len(l) > 1000 {
			t.Fatalf("typed line of %d bytes", len(l))
		}
	}
	out, _ := exec.Command("sh", "-c", typed).CombinedOutput()
	f := &cmdFilter{}
	got, done, code := f.feed(out)
	if !done || code != 1 || string(got) != "a; b https://x.example/?q=1\nno newline" {
		t.Fatalf("done=%v code=%d %q (raw %q)", done, code, got, out)
	}
}
