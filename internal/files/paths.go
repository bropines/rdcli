package files

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Remote path helpers. Windows peers use "\" and list their drives at "/";
// everything else uses "/" (rdweb paths.ts). Names that come from the peer
// are untrusted and are checked before they become local paths.

const backslash = 0x5c

func isDriveLetter(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// isDrive reports whether s is "C:".
func isDrive(s string) bool { return len(s) == 2 && isDriveLetter(s[0]) && s[1] == ':' }

func remoteSep(windows bool) string {
	if windows {
		return `\`
	}
	return "/"
}

// trimRemote drops trailing separators.
func trimRemote(p string, windows bool) string {
	if windows {
		return strings.TrimRight(p, `\/`)
	}
	return strings.TrimRight(p, "/")
}

func lastRemoteSep(p string, windows bool) int {
	if windows {
		return strings.LastIndexAny(p, `\/`)
	}
	return strings.LastIndexByte(p, '/')
}

func endsWithRemoteSep(p string, windows bool) bool {
	return p != "" && (p[len(p)-1] == '/' || windows && p[len(p)-1] == backslash)
}

// joinRemote joins a remote folder and a name with the peer's separator.
func joinRemote(dir, name string, windows bool) string {
	switch {
	case name == "":
		return dir
	case dir == "":
		return name
	}
	// On Windows the drive list lives at "/": "/" + "C:" is the root of C:.
	if windows && dir == "/" {
		if isDrive(name) {
			return name + `\`
		}
		return name
	}
	if endsWithRemoteSep(dir, windows) {
		return dir + name
	}
	return dir + remoteSep(windows) + name
}

// parentRemote is the parent of a remote path; Windows drive roots go up to
// the drive list "/".
func parentRemote(p string, windows bool) string {
	t := trimRemote(p, windows)
	if windows {
		if p == "/" || isDrive(t) {
			return "/"
		}
		i := lastRemoteSep(t, true)
		if i < 0 {
			return "/"
		}
		parent := t[:i]
		switch {
		case isDrive(parent):
			return parent + `\`
		case parent == "":
			return "/"
		}
		return parent
	}
	i := strings.LastIndexByte(t, '/')
	if i <= 0 {
		return "/"
	}
	return t[:i]
}

// baseRemote is the last component of a remote path ("C:" for "C:\").
func baseRemote(p string, windows bool) string {
	t := trimRemote(p, windows)
	return t[lastRemoteSep(t, windows)+1:]
}

// samePath reports whether two spellings name the same remote folder.
func samePath(a, b string, windows bool) bool {
	if a == b {
		return true
	}
	norm := func(p string) string {
		t := trimRemote(p, windows)
		if windows {
			t = strings.ToLower(strings.ReplaceAll(t, "/", `\`))
		}
		return t
	}
	return norm(a) == norm(b)
}

// relRemote returns p relative to root ("" for root itself).
func relRemote(root, p string, windows bool) (string, bool) {
	norm := func(s string) string {
		if windows {
			s = strings.ReplaceAll(s, "/", `\`)
		}
		return trimRemote(s, windows)
	}
	r, q := norm(root), norm(p)
	eq := func(a, b string) bool {
		if windows {
			return strings.EqualFold(a, b)
		}
		return a == b
	}
	if eq(r, q) {
		return "", true
	}
	r += remoteSep(windows)
	if len(q) > len(r) && eq(q[:len(r)], r) {
		return q[len(r):], true
	}
	return "", false
}

// safeSegments turns a relative name from the peer into path segments,
// refusing anything that could leave the target folder: "..", absolute
// paths, drive letters, NUL bytes (rdweb safeRelativeSegments; upstream
// validate_file_name_no_traversal does the same on the controlled side).
// Both separators split, whatever the peer runs.
func safeSegments(name string) ([]string, error) {
	if strings.ContainsRune(name, 0) {
		return nil, fmt.Errorf("invalid file name %q", name)
	}
	if name != "" && (name[0] == '/' || name[0] == backslash) || len(name) >= 2 && isDrive(name[:2]) {
		return nil, fmt.Errorf("absolute path not allowed: %q", name)
	}
	var segs []string
	for _, s := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == backslash }) {
		switch s {
		case ".":
		case "..":
			return nil, fmt.Errorf("path traversal not allowed: %q", name)
		default:
			segs = append(segs, s)
		}
	}
	return segs, nil
}

// localRel turns checked segments into a local relative path. goos is
// runtime.GOOS: on Windows a ":" would address an alternate data stream.
func localRel(segs []string, goos string) (string, error) {
	if len(segs) == 0 {
		return "", fmt.Errorf("empty file name")
	}
	for _, s := range segs {
		if goos == "windows" && strings.ContainsAny(s, `:<>"|?*`) {
			return "", fmt.Errorf("%q is not a valid file name on this system", s)
		}
	}
	rel := filepath.Join(segs...)
	// Also refuses reserved device names (NUL, COM1) on Windows.
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("%q is not a valid file name on this system", strings.Join(segs, "/"))
	}
	return rel, nil
}

// localName is the downloaded item's own name as a local name ("C:" gives
// "C", ".." gives "download").
func localName(name string) string {
	clean := strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || strings.ContainsRune(`<>:"/\|?*`, r) {
			return -1
		}
		return r
	}, name))
	if clean == "" || clean == "." || clean == ".." {
		return "download"
	}
	return clean
}

// versionNumber is hbb_common's get_version_number: 1.4.2 gives 1004002.
func versionNumber(v string) int64 {
	var n int64
	parts := strings.SplitN(strings.TrimSpace(v), ".", 4)
	for i := range 3 {
		var x int64
		if i < len(parts) {
			for _, c := range parts[i] {
				if c < '0' || c > '9' {
					break
				}
				x = x*10 + int64(c-'0')
			}
		}
		n = n*1000 + x
	}
	return n
}
