package term

import "testing"

func TestSanitize(t *testing.T) {
	in := "ok \x1b]0;pwned\x07\x1b[2Jdone\u009b31m\r\nз"
	if got := Sanitize(in); got != "ok ]0;pwned[2Jdone31mз" {
		t.Fatalf("%q", got)
	}
}
