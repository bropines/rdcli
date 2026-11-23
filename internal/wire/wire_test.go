package wire

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

func TestHeaderSizes(t *testing.T) {
	cases := map[int]int{0: 1, 0x3F: 1, 0x40: 2, 0x3FFF: 2, 0x4000: 3, 0x3FFFFF: 3, 0x400000: 4, MaxFrame: 4}
	for n, want := range cases {
		h, err := AppendHeader(nil, n)
		if err != nil || len(h) != want {
			t.Fatalf("n=%d: header %x err %v", n, h, err)
		}
	}
	if _, err := AppendHeader(nil, MaxFrame+1); err == nil {
		t.Fatal("overflow accepted")
	}
}

// Byte-exact with hbb_common's encoder for the boundary cases.
func TestHeaderBytes(t *testing.T) {
	h, _ := AppendHeader(nil, 0x3F)
	if !bytes.Equal(h, []byte{0xFC}) {
		t.Fatalf("%x", h)
	}
	h, _ = AppendHeader(nil, 0x40)
	if !bytes.Equal(h, []byte{0x01, 0x01}) {
		t.Fatalf("%x", h)
	}
	h, _ = AppendHeader(nil, 0x4000)
	if !bytes.Equal(h, []byte{0x02, 0x00, 0x01}) {
		t.Fatalf("%x", h)
	}
}

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 63, 64, 1000, 0x3FFF, 0x4000, 70000, 0x400000} {
		msg := bytes.Repeat([]byte{7}, n)
		h, _ := AppendHeader(nil, n)
		r := bufio.NewReader(bytes.NewReader(append(h, msg...)))
		got, err := ReadFrame(r, DefaultMaxPacket)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("n=%d err %v len %d", n, err, len(got))
		}
	}
}

func TestLimit(t *testing.T) {
	h, _ := AppendHeader(nil, 1000)
	if _, err := ReadFrame(bufio.NewReader(bytes.NewReader(h)), 999); err == nil {
		t.Fatal("over-limit frame accepted")
	}
}

func TestTCPRawSwitch(t *testing.T) {
	a, b := net.Pipe()
	ta, tb := NewTCP(a), NewTCP(b)
	go func() {
		ta.Send([]byte("framed"))
		ta.SetRaw()
		ta.Send([]byte("raw bytes"))
	}()
	got, err := tb.Recv()
	if err != nil || string(got) != "framed" {
		t.Fatal(string(got), err)
	}
	tb.SetRaw()
	got, err = tb.Recv()
	if err != nil || string(got) != "raw bytes" {
		t.Fatal(string(got), err)
	}
}

func TestWithPort(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":      "example.com:21116",
		"example.com:1":    "example.com:1",
		"10.0.0.1":         "10.0.0.1:21116",
		"::1":              "[::1]:21116",
		"[2001:db8::1]":    "[2001:db8::1]:21116",
		"[2001:db8::1]:99": "[2001:db8::1]:99",
	} {
		if got := WithPort(in, 21116); got != want {
			t.Fatalf("%s -> %s, want %s", in, got, want)
		}
	}
}
