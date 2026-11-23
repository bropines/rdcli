package forward

import "testing"

func TestParseSpec(t *testing.T) {
	cases := map[string]Spec{
		"2222:22":                 {Bind: "127.0.0.1:2222", Target: Target{"localhost", 22}},
		"2222:localhost:22":       {Bind: "127.0.0.1:2222", Target: Target{"localhost", 22}},
		"8080:10.0.0.5:80":        {Bind: "127.0.0.1:8080", Target: Target{"10.0.0.5", 80}},
		"0.0.0.0:8080:web:80":     {Bind: "0.0.0.0:8080", Target: Target{"web", 80}},
		"[::1]:8080:[fd00::5]:80": {Bind: "[::1]:8080", Target: Target{"fd00::5", 80}},
		"13389:localhost:3389":    {Bind: "127.0.0.1:13389", Target: Target{"localhost", 3389}},
		":2222:host:22":           {Bind: "127.0.0.1:2222", Target: Target{"host", 22}},
	}
	for in, want := range cases {
		got, err := ParseSpec(in)
		if err != nil || got != want {
			t.Fatalf("%s: %+v %v, want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "22", "x:host:22", "22:host:0", "22:host:99999", "1:2:3:4:5"} {
		if _, err := ParseSpec(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestParseTarget(t *testing.T) {
	for in, want := range map[string]Target{
		"22":            {"localhost", 22},
		"localhost:22":  {"localhost", 22},
		"10.1.1.1:3389": {"10.1.1.1", 3389},
		"[fd00::1]:80":  {"fd00::1", 80},
		":22":           {"localhost", 22},
	} {
		got, err := ParseTarget(in)
		if err != nil || got != want {
			t.Fatalf("%s: %+v %v", in, got, err)
		}
	}
	if _, err := ParseTarget("host"); err == nil {
		t.Fatal("missing port accepted")
	}
}

func TestWindows(t *testing.T) {
	w := &recvWindow{remaining: ChannelWindow}
	if !w.accept(1) || w.remaining != ChannelWindow-MinFrameCharge {
		t.Fatal("a tiny frame must cost the minimum charge")
	}
	total := 0
	for total < 10*int(ChannelWindow) {
		if !w.accept(MaxFrame) {
			t.Fatalf("overran after %d bytes", total)
		}
		w.drain(MaxFrame)
		total += MaxFrame
	}
	w2 := &recvWindow{remaining: 100}
	if w2.accept(101) {
		t.Fatal("overrun accepted")
	}
	c := newSendCredit(10 * ChannelWindow)
	if c.credit != MaxSendCredit {
		t.Fatal("credit not capped")
	}
	c = newSendCredit(InitialWindow)
	c.raiseInitial(ChannelWindow)
	if c.credit != ChannelWindow {
		t.Fatalf("raise to %d", c.credit)
	}
	c.raiseInitial(1) // smaller than initial: nothing
	if c.credit != ChannelWindow {
		t.Fatal("raise with a small window changed credit")
	}
}
