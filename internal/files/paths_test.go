package files

import (
	"runtime"
	"slices"
	"testing"
)

func TestJoinRemote(t *testing.T) {
	for _, tc := range []struct {
		dir, name string
		windows   bool
		want      string
	}{
		{"/home/u", "a.txt", false, "/home/u/a.txt"},
		{"/home/u/", "a.txt", false, "/home/u/a.txt"},
		{"/", "etc", false, "/etc"},
		{"", "a", false, "a"},
		{"/a", "", false, "/a"},
		{`C:\Users`, "u", true, `C:\Users\u`},
		{`C:\`, "Users", true, `C:\Users`},
		{"C:/Users/", "u", true, "C:/Users/u"},
		{"/", "C:", true, `C:\`}, // the drive list
		{"/", "share", true, "share"},
		{`\\host\share`, "x", true, `\\host\share\x`},
	} {
		if got := joinRemote(tc.dir, tc.name, tc.windows); got != tc.want {
			t.Errorf("joinRemote(%q, %q, %v) = %q, want %q", tc.dir, tc.name, tc.windows, got, tc.want)
		}
	}
}

func TestParentAndBaseRemote(t *testing.T) {
	for _, tc := range []struct {
		path         string
		windows      bool
		parent, base string
	}{
		{"/home/u/a.txt", false, "/home/u", "a.txt"},
		{"/home/u/", false, "/home", "u"},
		{"/home", false, "/", "home"},
		{"/", false, "/", ""},
		{`a\b`, false, "/", `a\b`}, // a backslash is a plain character there
		{`C:\Users\u`, true, `C:\Users`, "u"},
		{`C:\Users`, true, `C:\`, "Users"},
		{"C:/Users/u/", true, "C:/Users", "u"},
		{`C:\`, true, "/", "C:"},
		{"C:", true, "/", "C:"},
		{"/", true, "/", ""},
	} {
		if got := parentRemote(tc.path, tc.windows); got != tc.parent {
			t.Errorf("parentRemote(%q, %v) = %q, want %q", tc.path, tc.windows, got, tc.parent)
		}
		if got := baseRemote(tc.path, tc.windows); got != tc.base {
			t.Errorf("baseRemote(%q, %v) = %q, want %q", tc.path, tc.windows, got, tc.base)
		}
	}
}

func TestSamePathAndRel(t *testing.T) {
	if !samePath("/a/b/", "/a/b", false) || samePath("/a/B", "/a/b", false) || samePath(`/a\b`, "/a/b", false) {
		t.Error("unix samePath")
	}
	if !samePath(`C:\Users\U\`, "c:/users/u", true) || samePath(`C:\a`, `C:\b`, true) {
		t.Error("windows samePath")
	}
	for _, tc := range []struct {
		root, path string
		windows    bool
		rel        string
		ok         bool
	}{
		{"/srv/d", "/srv/d/x/y", false, "x/y", true},
		{"/srv/d/", "/srv/d", false, "", true},
		{"/srv/d", "/srv/dx", false, "", false},
		{"/srv/d", "/srv", false, "", false},
		{"/", "/etc", false, "etc", true},
		{`C:\Data`, `c:\data\Sub\x`, true, `Sub\x`, true},
		{`C:\Data`, "C:/Data/Sub", true, "Sub", true},
		{`C:\Data`, `C:\Database`, true, "", false},
	} {
		rel, ok := relRemote(tc.root, tc.path, tc.windows)
		if rel != tc.rel || ok != tc.ok {
			t.Errorf("relRemote(%q, %q, %v) = %q, %v; want %q, %v", tc.root, tc.path, tc.windows, rel, ok, tc.rel, tc.ok)
		}
	}
}

func TestSafeSegments(t *testing.T) {
	for name, want := range map[string][]string{
		"a.txt":          {"a.txt"},
		"sub/b.txt":      {"sub", "b.txt"},
		`sub\deep\b.txt`: {"sub", "deep", "b.txt"},
		"./a//b/.":       {"a", "b"},
		"..a/b..":        {"..a", "b.."},
		"":               nil,
	} {
		got, err := safeSegments(name)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("safeSegments(%q) = %q, %v; want %q", name, got, err, want)
		}
	}
	for _, name := range []string{
		"..", "../a", "a/../b", `a\..\b`, `..\a`, "a/..",
		"/etc/passwd", `\Windows`, `\\host\share\x`, "C:", `C:\x`, "c:x", "C:/x",
		"a\x00b",
	} {
		if got, err := safeSegments(name); err == nil {
			t.Errorf("safeSegments(%q) = %q, want an error", name, got)
		}
	}
}

func TestLocalRel(t *testing.T) {
	if _, err := localRel(nil, "linux"); err == nil {
		t.Error("an empty name must be refused")
	}
	if rel, err := localRel([]string{"a", "b.txt"}, runtime.GOOS); err != nil || rel == "" {
		t.Errorf("plain name refused: %v", err)
	}
	// On Windows "name:stream" would write an alternate data stream.
	if _, err := localRel([]string{"a", "b:evil"}, "windows"); err == nil {
		t.Error("a colon must be refused on Windows")
	}
	if runtime.GOOS == "windows" {
		if _, err := localRel([]string{"sub", "NUL"}, runtime.GOOS); err == nil {
			t.Error("a device name must be refused on Windows")
		}
	}
}

func TestLocalName(t *testing.T) {
	for in, want := range map[string]string{
		"a.txt": "a.txt", "C:": "C", "..": "download", "": "download", ".": "download",
		`we<i>rd|na"me?*`: "weirdname", " x ": "x",
	} {
		if got := localName(in); got != want {
			t.Errorf("localName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVersionNumber(t *testing.T) {
	for in, want := range map[string]int64{
		"1.4.2": 1_004_002, "1.1.10": 1_001_010, "1.4.3-1": 1_004_003, "1.2": 1_002_000, "": 0, "x": 0,
	} {
		if got := versionNumber(in); got != want {
			t.Errorf("versionNumber(%q) = %d, want %d", in, got, want)
		}
	}
	if versionNumber("1.1.9") >= digestSince || versionNumber("1.4.2") < resumeSince {
		t.Error("version thresholds")
	}
}
