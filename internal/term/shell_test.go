package term

import "testing"

func TestEscaper(t *testing.T) {
	cases := []struct {
		in     []string
		out    string
		action escAction
	}{
		{[]string{"ls\r"}, "ls\r", escNone},
		{[]string{"~."}, "", escDisconnect},
		{[]string{"echo\r", "~."}, "echo\r", escDisconnect},
		{[]string{"a~."}, "a~.", escNone},
		{[]string{"~~"}, "~", escNone},
		{[]string{"~x"}, "~x", escNone},
		{[]string{"~", "."}, "", escDisconnect},
		{[]string{"~?"}, "", escHelp},
	}
	for _, c := range cases {
		e := &escaper{char: '~', enabled: true, lineStart: true}
		var got []byte
		var act escAction
		for _, chunk := range c.in {
			o, a := e.feed([]byte(chunk))
			got = append(got, o...)
			if a != escNone {
				act = a
			}
		}
		if string(got) != c.out || act != c.action {
			t.Fatalf("%q: got %q/%v, want %q/%v", c.in, got, act, c.out, c.action)
		}
	}
	e := &escaper{char: '~', enabled: false, lineStart: true}
	if o, a := e.feed([]byte("~.")); string(o) != "~." || a != escNone {
		t.Fatal("disabled escaper interfered")
	}
}
