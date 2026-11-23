package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseConfigString(t *testing.T) {
	s, err := ParseConfigString(" 0nI9cnQtF3VzNUUyF3RKRDNudHc3lUMDB3MZBjbOBVQrAHWphEbuVzaLVnVl9kI6ISeltmIsISbvNmLlxGctFGel5Cbl5WYw9yL6MHc0RHaiojIpBXYiwiI3ETMxIjOt92YuUGbw1WY4VmLkJnI6ISehxWZyJCLi02bj5SZsBXbhhXZuQmciojI0N3boJye\n")
	if err != nil {
		t.Fatal(err)
	}
	want := Server{IDServer: "rd.example.com", Relay: "rd.example.com:21117", API: "https://panel.example.com", Key: "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="}
	if *s != want {
		t.Fatalf("%+v", *s)
	}
	if _, err := ParseConfigString("hello"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestSaveLoadAndPeers(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RDCLI_CONFIG", filepath.Join(dir, "sub", "config.json"))
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	c.Servers["home"] = &Server{IDServer: "rd.example.com", Key: "k", Token: "secret"}
	c.Remember("123456789", "home", []byte{1, 2, 3})
	c.Peers["123456789"].Alias = "office"
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(c.File())
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
	c2, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	name, s, err := c2.Server("")
	if err != nil || name != "home" || s.Token != "secret" {
		t.Fatalf("single profile is the default: %q %v %v", name, s, err)
	}
	if id, p := c2.ResolvePeer("Office"); id != "123456789" || p == nil {
		t.Fatalf("alias: %q", id)
	}
	if id, _ := c2.ResolvePeer("987 654 321"); id != "987654321" {
		t.Fatalf("spaces: %q", id)
	}
	if h := c2.RememberedHash("123456789"); len(h) != 3 {
		t.Fatalf("hash %v", h)
	}
	if !c2.Forget("123456789") || c2.RememberedHash("123456789") != nil {
		t.Fatal("forget")
	}
	if _, ok := c2.Peers["123456789"]; !ok {
		t.Fatal("forget dropped the alias too")
	}
	if _, _, err := c2.Server("nope"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestRustDeskOptions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "RustDesk2.toml")
	os.WriteFile(p, []byte(`rendezvous_server = 'x:21116'
nat_type = 1

[options]
custom-rendezvous-server = 'rd.example.com'
relay-server = "relay.example.com:21117"
key = 'OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw='
api-server = 'https://panel.example.com'

[other]
key = 'not this'
`), 0o600)
	o, err := RustDeskOptions(p)
	if err != nil {
		t.Fatal(err)
	}
	if o["custom-rendezvous-server"] != "rd.example.com" || o["relay-server"] != "relay.example.com:21117" ||
		o["key"] != "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=" || o["api-server"] != "https://panel.example.com" {
		t.Fatalf("%v", o)
	}
}
