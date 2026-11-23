package cli

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bropines/rdcli/internal/config"
)

func TestParseFlagsInterspersed(t *testing.T) {
	fs := newFlagSet("x", "")
	v := fs.Bool("v", false, "")
	name := fs.String("name", "", "")
	pos, err := parseFlags(fs, []string{"123", "-v", "--name", "me", "extra", "--", "-c", "ls -l"})
	if err != nil {
		t.Fatal(err)
	}
	if !*v || *name != "me" || !reflect.DeepEqual(pos, []string{"123", "extra", "-c", "ls -l"}) {
		t.Fatalf("v=%v name=%q pos=%q", *v, *name, pos)
	}
}

func TestSplitPeerPath(t *testing.T) {
	cases := []struct {
		in, peer, path string
		remote         bool
	}{
		{"123:/etc/hosts", "123", "/etc/hosts", true},
		{"123:", "123", "", true},
		{`123:C:\Users\me`, "123", `C:\Users\me`, true},
		{"office:docs/a.txt", "office", "docs/a.txt", true},
		{`C:\local\file`, "", `C:\local\file`, false},
		{"C:/local/file", "", "C:/local/file", false},
		{"./file", "", "./file", false},
		{"/abs/file", "", "/abs/file", false},
	}
	for _, c := range cases {
		p, path, r := splitPeerPath(c.in)
		if p != c.peer || path != c.path || r != c.remote {
			t.Fatalf("%q -> %q %q %v", c.in, p, path, r)
		}
	}
}

func TestProfileTokenStaysWithItsServer(t *testing.T) {
	t.Setenv("RDCLI_CONFIG", filepath.Join(t.TempDir(), "c.json"))
	cfg, _ := config.Load()
	cfg.Servers["home"] = &config.Server{IDServer: "rd.example.com", Key: "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=", Token: "secret"}
	cfg.Save()
	f := &connFlags{}
	tg, err := f.resolve("123")
	if err != nil || tg.server.Token != "secret" {
		t.Fatalf("own server: %v %q", err, tg.server.Token)
	}
	f = &connFlags{idServer: "evil.example.com"}
	if tg, _ = f.resolve("123"); tg.server.Token != "" {
		t.Fatal("the profile token went to another ID server")
	}
	f = &connFlags{idServer: "other.example.com", token: "explicit"}
	if tg, _ = f.resolve("123"); tg.server.Token != "explicit" {
		t.Fatal("an explicit token was dropped")
	}
}
