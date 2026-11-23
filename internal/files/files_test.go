package files

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bropines/rdcli/internal/pb"
)

const mtime = 1_700_000_000

func text(n int) []byte { return bytes.Repeat([]byte("all work and no play. "), n/22+1)[:n] }

func noise(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func wantFile(t *testing.T, path string, data []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("%s: %d bytes, want %d (content differs)", path, len(got), len(data))
	}
}

func wantNoParts(t *testing.T, dir string) {
	t.Helper()
	filepath.WalkDir(dir, func(path string, _ os.DirEntry, _ error) error {
		if strings.HasSuffix(path, partSuffix) {
			t.Errorf("left behind %s", path)
		}
		return nil
	})
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, time.Time{}, time.Unix(mtime, 0)); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------- listings

func TestListAndHome(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.put("/home/u/a.txt", text(10), mtime)
	p.put("/home/u/docs/b.txt", text(20), mtime)
	c := p.start(true)
	ctx := testCtx(t)

	// The listing peers send after login must not answer this request.
	got, err := c.List(ctx, "/home/u/docs", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "b.txt" || got[0].Size != 20 || got[0].IsDir || got[0].ModTime.Unix() != mtime {
		t.Fatalf("docs listing: %+v", got)
	}
	for _, dir := range []string{"", "~"} {
		got, err = c.List(ctx, dir, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].Name != "a.txt" || got[1].Name != "docs" || !got[1].IsDir {
			t.Fatalf("home listing %q: %+v", dir, got)
		}
	}
	if home, err := c.Home(ctx); err != nil || home != "/home/u" {
		t.Fatalf("home = %q, %v", home, err)
	}
	if got, err = c.List(ctx, "~/docs", false); err != nil || len(got) != 1 {
		t.Fatalf("~/docs: %+v, %v", got, err)
	}
	var re *RemoteError
	if _, err = c.List(ctx, "/nope", false); !errors.As(err, &re) || !strings.Contains(re.Msg, "os error 2") {
		t.Fatalf("missing folder: %v", err)
	}
	// The session still works after an error.
	if _, err = c.List(ctx, "/home/u", false); err != nil {
		t.Fatal(err)
	}
}

func TestListWithoutInitialListing(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.put("/home/u/a.txt", nil, 0)
	c := p.start(false)
	got, err := c.List(testCtx(t), "", false)
	if err != nil || len(got) != 1 || !got[0].ModTime.IsZero() {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestListTimeoutThenLateAnswer(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.put("/home/u/a/1", nil, 0)
	p.put("/home/u/b/2", nil, 0)
	c := p.start(true)
	c.timeout = 50 * time.Millisecond
	swallow := true
	var held *pb.Message
	p.script = func(m *pb.Message) bool {
		if swallow && m.GetFileAction().GetReadDir() != nil {
			swallow, held = false, m
			return true
		}
		return false
	}
	ctx := testCtx(t)
	if _, err := c.List(ctx, "/home/u/a", false); !errors.Is(err, ErrTimeout) {
		t.Fatalf("want a timeout, got %v", err)
	}
	c.timeout = 5 * time.Second
	// The late answer for "a" arrives while "b" is being asked for.
	p.mu.Lock()
	p.handle(held)
	p.mu.Unlock()
	got, err := c.List(ctx, "/home/u/b", false)
	if err != nil || len(got) != 1 || got[0].Name != "2" {
		t.Fatalf("%+v, %v", got, err)
	}
}

func TestWindowsListing(t *testing.T) {
	p := newFakePeer(t, true, `C:\Users\u`)
	p.put(`C:\Users\u\a.txt`, text(5), mtime)
	c := p.start(true)
	ctx := testCtx(t)
	if !c.Windows() {
		t.Fatal("not detected as Windows")
	}
	// Other spellings of a folder are still matched to the answer.
	if got, err := c.List(ctx, `~\`, false); err != nil || len(got) != 1 {
		t.Fatalf("%+v, %v", got, err)
	}
	if got := c.Join("/", "C:"); got != `C:\` {
		t.Fatalf("join = %q", got)
	}
}

// --------------------------------------------------------------- downloads

func TestDownloadFile(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	data := text(300_000) // compressible: arrives as zstd blocks
	p.put("/home/u/a.txt", data, mtime)
	c := p.start(true)
	ctx := testCtx(t)
	dir := t.TempDir()

	var last Progress
	calls := 0
	err := c.Download(ctx, "~/a.txt", dir, TransferOptions{Progress: func(pr Progress) { last = pr; calls++ }})
	if err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(dir, "a.txt"), data)
	if st, _ := os.Stat(filepath.Join(dir, "a.txt")); st.ModTime().Unix() != mtime {
		t.Errorf("mtime = %v", st.ModTime())
	}
	if calls == 0 || last.Done != int64(len(data)) || last.Total != last.Done || last.Files != 1 || last.FilesDone != 1 {
		t.Errorf("last progress: %+v (%d calls)", last, calls)
	}
	// A new name, and overwriting it.
	dst := filepath.Join(dir, "copy.txt")
	write(t, dst, []byte("old"))
	if err := c.Download(ctx, "/home/u/a.txt", dst, TransferOptions{}); err != nil {
		t.Fatal(err)
	}
	wantFile(t, dst, data)
	wantNoParts(t, dir)
}

func TestDownloadDirectory(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	a, b := text(1000), noise(200_000)
	p.put("/srv/data/a.txt", a, mtime)
	p.put("/srv/data/sub/b.bin", b, mtime)
	p.put("/srv/data/sub/empty.txt", nil, mtime)
	p.mkdirAll("/srv/data/hollow/deep")
	p.chunk = 64 << 10
	c := p.start(true)
	ctx := testCtx(t)
	dir := t.TempDir()

	if err := c.Download(ctx, "/srv/data", dir, TransferOptions{}); !errors.Is(err, ErrIsDirectory) {
		t.Fatalf("want ErrIsDirectory, got %v", err)
	}
	p.waitCancelled(1)
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("refused download wrote %v", entries)
	}

	out := filepath.Join(dir, "out")
	var last Progress
	if err := c.Download(ctx, "/srv/data", out, TransferOptions{Recursive: true, Progress: func(pr Progress) { last = pr }}); err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(out, "a.txt"), a)
	wantFile(t, filepath.Join(out, "sub", "b.bin"), b)
	wantFile(t, filepath.Join(out, "sub", "empty.txt"), nil)
	if st, err := os.Stat(filepath.Join(out, "hollow", "deep")); err != nil || !st.IsDir() {
		t.Errorf("empty folder not recreated: %v", err)
	}
	if last.FilesDone != 3 || last.Done != int64(len(a)+len(b)) || last.Total != last.Done {
		t.Errorf("last progress: %+v", last)
	}
	// Into an existing folder: under its remote name.
	if err := c.Download(ctx, "/srv/data/", dir, TransferOptions{Recursive: true}); err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(dir, "data", "sub", "b.bin"), b)
	wantNoParts(t, dir)
}

func TestDownloadEmptyDirectory(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.mkdirAll("/srv/void")
	p.noEmptyDirs = true
	c := p.start(true)
	out := filepath.Join(t.TempDir(), "void")
	if err := c.Download(testCtx(t), "/srv/void", out, TransferOptions{Recursive: true}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(out); err != nil || !st.IsDir() {
		t.Fatalf("folder not created: %v", err)
	}
}

func confirms(p *fakePeer) (skips int, offsets []uint32) {
	for _, m := range p.sent() {
		if sc := m.GetFileAction().GetSendConfirm(); sc != nil {
			if sc.GetSkip() {
				skips++
			} else {
				offsets = append(offsets, sc.GetOffsetBlk())
			}
		}
	}
	return
}

func TestDownloadSkipAndResume(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	a, b := text(5000), noise(5000)
	p.put("/srv/d/a.txt", a, mtime)
	p.put("/srv/d/b.bin", b, mtime)
	p.chunk = 1024
	c := p.start(true)
	ctx := testCtx(t)
	root := t.TempDir()
	out := filepath.Join(root, "d")

	// SkipExisting keeps whatever is there.
	write(t, filepath.Join(out, "a.txt"), []byte("mine"))
	var last Progress
	err := c.Download(ctx, "/srv/d", root, TransferOptions{Recursive: true, SkipExisting: true, Progress: func(pr Progress) { last = pr }})
	if err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(out, "a.txt"), []byte("mine"))
	wantFile(t, filepath.Join(out, "b.bin"), b)
	if last.FilesSkipped != 1 || last.FilesDone != 1 || last.Total != int64(len(b)) {
		t.Errorf("last progress: %+v", last)
	}

	// Resume: a.txt differs and is fetched again, b.bin is identical.
	if err := c.Download(ctx, "/srv/d", root, TransferOptions{Recursive: true, Resume: true}); err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(out, "a.txt"), a)
	if skips, _ := confirms(p); skips != 2 {
		t.Errorf("%d skips, want 2", skips)
	}

	// Resume continues a partial copy from where it stopped.
	os.Remove(filepath.Join(out, "b.bin"))
	write(t, filepath.Join(out, "b.bin"+partSuffix), b[:1500])
	if err := c.Download(ctx, "/srv/d", root, TransferOptions{Recursive: true, Resume: true}); err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(out, "b.bin"), b)
	if _, offsets := confirms(p); offsets[len(offsets)-1] != 1500 {
		t.Errorf("offsets %v, want the last to be 1500", offsets)
	}
	// Without Resume a stale part is not trusted.
	os.Remove(filepath.Join(out, "b.bin"))
	write(t, filepath.Join(out, "b.bin"+partSuffix), []byte("garbage"))
	if err := c.Download(ctx, "/srv/d/b.bin", out, TransferOptions{}); err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(out, "b.bin"), b)

	// A job whose only file is skipped ends with the peer's "skipped".
	if err := c.Download(ctx, "/srv/d/b.bin", out, TransferOptions{SkipExisting: true}); err != nil {
		t.Fatal(err)
	}
	wantNoParts(t, out)
}

func TestDownloadRejectsUnsafeNames(t *testing.T) {
	for _, name := range []string{"../evil", `..\evil`, "sub/../../evil", "/etc/evil", `C:\evil`, `\\host\share\evil`, "a\x00b"} {
		p := newFakePeer(t, false, "/home/u")
		p.script = func(m *pb.Message) bool {
			s := m.GetFileAction().GetSend()
			if s == nil {
				return false
			}
			p.emitDir(s.GetId(), s.GetPath(), []*pb.FileEntry{
				{EntryType: pb.FileType_File, Name: "ok.txt", Size: 1},
				{EntryType: pb.FileType_File, Name: name, Size: 1},
			})
			return true
		}
		c := p.start(true)
		root := t.TempDir()
		out := filepath.Join(root, "in", "out")
		err := c.Download(testCtx(t), "/srv/d", out, TransferOptions{Recursive: true})
		if err == nil || !strings.Contains(err.Error(), "unsafe file name") {
			t.Fatalf("%q: got %v", name, err)
		}
		p.waitCancelled(1)
		if entries, _ := os.ReadDir(root); len(entries) != 0 {
			t.Fatalf("%q: wrote %v", name, entries)
		}
	}
}

func TestDownloadRemoteError(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	c := p.start(true)
	dir := t.TempDir()
	var re *RemoteError
	err := c.Download(testCtx(t), "/nope", dir, TransferOptions{})
	if !errors.As(err, &re) || re.Msg != "Not exists" || re.Path != "/nope" {
		t.Fatalf("got %v", err)
	}
}

// A peer that fails in the middle of a file: the part is removed.
func TestDownloadErrorMidFile(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.put("/srv/a.txt", text(5000), mtime)
	p.chunk = 1000
	p.hold = true
	c := p.start(true)
	p.script = func(m *pb.Message) bool {
		if sc := m.GetFileAction().GetSendConfirm(); sc != nil {
			p.handle(m) // one block, then it holds
			p.emitError(sc.GetId(), "Input/output error (os error 5)", 1)
			return true
		}
		return false
	}
	dir := t.TempDir()
	var re *RemoteError
	if err := c.Download(testCtx(t), "/srv/a.txt", dir, TransferOptions{}); !errors.As(err, &re) {
		t.Fatalf("got %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left %v", entries)
	}
}

func TestDownloadOversizeBlock(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	// 8 MiB of zeros is a tiny zstd frame.
	p.put("/srv/bomb", make([]byte, 2*maxBlockSize), mtime)
	p.chunk = 2 * maxBlockSize
	c := p.start(true)
	dir := t.TempDir()
	err := c.Download(testCtx(t), "/srv/bomb", dir, TransferOptions{})
	if err == nil || !strings.Contains(err.Error(), "bad compressed block") {
		t.Fatalf("got %v", err)
	}
	p.waitCancelled(1)
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left %v", entries)
	}
}

func TestDownloadCancel(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.put("/srv/a.bin", noise(5000), mtime)
	p.chunk = 1000
	p.hold = true
	c := p.start(true)
	ctx, cancel := context.WithCancel(testCtx(t))
	dir := t.TempDir()
	err := c.Download(ctx, "/srv/a.bin", dir, TransferOptions{Progress: func(pr Progress) {
		if pr.Name != "" {
			cancel()
		}
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	p.waitCancelled(1)
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("left %v", entries)
	}
	// The client is still usable.
	p.mu.Lock()
	p.hold = false
	p.mu.Unlock()
	if err := c.Download(testCtx(t), "/srv/a.bin", dir, TransferOptions{}); err != nil {
		t.Fatal(err)
	}
}

// Peers older than the digest dialogue just send the data.
func TestDownloadWithoutDigests(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.script = func(m *pb.Message) bool {
		s := m.GetFileAction().GetSend()
		if s == nil {
			return false
		}
		p.emitDir(s.GetId(), s.GetPath(), []*pb.FileEntry{
			{EntryType: pb.FileType_File, Name: "x/1.txt", Size: 3, ModifiedTime: mtime},
			{EntryType: pb.FileType_File, Name: "2.txt", Size: 0},
		})
		p.emitBlock(s.GetId(), 0, []byte("one"))
		p.emitBlock(s.GetId(), 0, nil)
		p.emitBlock(s.GetId(), 1, nil)
		p.emitDone(s.GetId(), 2)
		return true
	}
	c := p.start(true)
	out := filepath.Join(t.TempDir(), "o")
	if err := c.Download(testCtx(t), "/srv/d", out, TransferOptions{Recursive: true}); err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(out, "x", "1.txt"), []byte("one"))
	wantFile(t, filepath.Join(out, "2.txt"), nil)
}

func TestDownloadFromWindows(t *testing.T) {
	p := newFakePeer(t, true, `C:\Users\u`)
	p.put(`C:\Users\u\proj\src\main.go`, text(100), mtime)
	p.mkdirAll(`C:\Users\u\proj\Empty`)
	c := p.start(true)
	dir := t.TempDir()
	if err := c.Download(testCtx(t), `~\proj`, dir, TransferOptions{Recursive: true}); err != nil {
		t.Fatal(err)
	}
	wantFile(t, filepath.Join(dir, "proj", "src", "main.go"), text(100))
	if _, err := os.Stat(filepath.Join(dir, "proj", "Empty")); err != nil {
		t.Error(err)
	}
	// A drive root has no usable name of its own.
	if got := localName(baseRemote(`C:\`, true)); got != "C" {
		t.Errorf("local name of a drive = %q", got)
	}
}

// ----------------------------------------------------------------- uploads

func receive(p *fakePeer) *pb.FileTransferReceiveRequest {
	var r *pb.FileTransferReceiveRequest
	for _, m := range p.sent() {
		if x := m.GetFileAction().GetReceive(); x != nil {
			r = x
		}
	}
	return r
}

func TestUploadFile(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	c := p.start(true)
	ctx := testCtx(t)
	data := text(300_000)
	src := filepath.Join(t.TempDir(), "a.txt")
	write(t, src, data)

	var last Progress
	if err := c.Upload(ctx, src, "/srv/in/", TransferOptions{Progress: func(pr Progress) { last = pr }}); err != nil {
		t.Fatal(err)
	}
	f := p.file("/srv/in/a.txt")
	if f == nil || !bytes.Equal(f.data, data) || f.mtime != mtime {
		t.Fatalf("remote file: %+v", f != nil)
	}
	// One file is announced by its full path, without a name.
	if r := receive(p); r.GetPath() != "/srv/in/a.txt" || len(r.GetFiles()) != 1 || r.GetFiles()[0].GetName() != "" || r.GetTotalSize() != uint64(len(data)) {
		t.Errorf("announcement: %v", r)
	}
	if n, blocks := p.blocksSent(0); n != len(data) || blocks != 3 {
		t.Errorf("%d bytes in %d blocks", n, blocks)
	}
	if last.Done != int64(len(data)) || last.FilesDone != 1 || last.Total != last.Done {
		t.Errorf("last progress: %+v", last)
	}

	// A new name in the home folder, an empty file, and "~" alone.
	empty := filepath.Join(t.TempDir(), "empty")
	write(t, empty, nil)
	if err := c.Upload(ctx, empty, "~/x/renamed", TransferOptions{}); err != nil {
		t.Fatal(err)
	}
	if f := p.file("/home/u/x/renamed"); f == nil || len(f.data) != 0 {
		t.Fatal("empty file not created")
	}
	if err := c.Upload(ctx, src, "~", TransferOptions{}); err != nil {
		t.Fatal(err)
	}
	if p.file("/home/u/a.txt") == nil {
		t.Fatal("not uploaded into the home folder")
	}
}

func TestUploadDirectory(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.put("/srv/proj/keep.txt", []byte("remote copy"), 1)
	c := p.start(true)
	ctx := testCtx(t)
	src := filepath.Join(t.TempDir(), "proj")
	a, b := text(2000), noise(150_000)
	write(t, filepath.Join(src, "keep.txt"), a)
	write(t, filepath.Join(src, "sub", "b.jpg"), b)
	write(t, filepath.Join(src, ".secret"), []byte("s"))
	write(t, filepath.Join(src, ".git", "config"), []byte("g"))
	os.MkdirAll(filepath.Join(src, "hollow", "deep"), 0o777)

	if err := c.Upload(ctx, src, "/srv/", TransferOptions{}); !errors.Is(err, ErrIsDirectory) {
		t.Fatalf("want ErrIsDirectory, got %v", err)
	}
	// SkipExisting leaves the remote copy alone.
	var last Progress
	err := c.Upload(ctx, src, "/srv/", TransferOptions{Recursive: true, SkipExisting: true, Progress: func(pr Progress) { last = pr }})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.file("/srv/proj/keep.txt"); string(got.data) != "remote copy" {
		t.Fatalf("keep.txt overwritten")
	}
	if got := p.file("/srv/proj/sub/b.jpg"); got == nil || !bytes.Equal(got.data, b) || got.mtime != mtime {
		t.Fatalf("b.jpg wrong")
	}
	if !p.hasDir("/srv/proj/hollow/deep") {
		t.Error("empty folder not created")
	}
	if p.file("/srv/proj/.secret") != nil || p.file("/srv/proj/.git/config") != nil {
		t.Error("hidden files uploaded without ShowHidden")
	}
	if last.FilesSkipped != 1 || last.FilesDone != 1 || last.Files != 2 || last.Total != int64(len(b)) {
		t.Errorf("last progress: %+v", last)
	}
	if r := receive(p); r.GetPath() != "/srv/proj" || r.GetFiles()[1].GetName() != "sub/b.jpg" {
		t.Errorf("announcement: %v", r)
	}

	// The default overwrites; hidden files on request; the target is named.
	if err := c.Upload(ctx, src, "/srv/proj", TransferOptions{Recursive: true, ShowHidden: true}); err != nil {
		t.Fatal(err)
	}
	if got := p.file("/srv/proj/keep.txt"); !bytes.Equal(got.data, a) || got.mtime != mtime {
		t.Fatalf("keep.txt not overwritten")
	}
	if p.file("/srv/proj/.secret") == nil || p.file("/srv/proj/.git/config") == nil {
		t.Error("hidden files missing")
	}

	// Resume skips what is identical (size and time) and sends the rest.
	p.mu.Lock()
	p.files["/srv/proj/keep.txt"].mtime = 5
	p.log = nil
	p.mu.Unlock()
	if err := c.Upload(ctx, src, "/srv/proj", TransferOptions{Recursive: true, Resume: true}); err != nil {
		t.Fatal(err)
	}
	if n, _ := p.blocksSent(0); n != len(a) {
		t.Errorf("changed file: %d bytes sent", n)
	}
	if n, _ := p.blocksSent(1); n != 0 {
		t.Errorf("identical file: %d bytes sent", n)
	}
}

func TestUploadEmptyDirectory(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	c := p.start(true)
	src := filepath.Join(t.TempDir(), "void")
	os.MkdirAll(src, 0o777)
	if err := c.Upload(testCtx(t), src, "", TransferOptions{Recursive: true}); err != nil {
		t.Fatal(err)
	}
	if !p.hasDir("/home/u/void") {
		t.Fatal("folder not created")
	}
}

func TestUploadSkippedSingleFile(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.put("/srv/a.txt", []byte("remote copy"), 1)
	c := p.start(true)
	src := filepath.Join(t.TempDir(), "a.txt")
	write(t, src, text(100))
	if err := c.Upload(testCtx(t), src, "/srv/a.txt", TransferOptions{SkipExisting: true}); err != nil {
		t.Fatal(err)
	}
	if got := p.file("/srv/a.txt"); string(got.data) != "remote copy" {
		t.Fatal("overwritten")
	}
	// The job ends with "skipped" instead of done (rdweb upload.ts).
	msgs := p.sent()
	if e := msgs[len(msgs)-1].GetFileResponse().GetError(); e.GetError() != "skipped" {
		t.Errorf("last message: %v", msgs[len(msgs)-1])
	}
}

func TestUploadResume(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	data := noise(300_000)
	p.partials["/srv/big.bin"] = data[:100_000]
	c := p.start(true)
	src := filepath.Join(t.TempDir(), "big.bin")
	write(t, src, data)
	var first Progress
	err := c.Upload(testCtx(t), src, "/srv/big.bin", TransferOptions{Resume: true, Progress: func(pr Progress) {
		if first.Done == 0 {
			first = pr
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if f := p.file("/srv/big.bin"); f == nil || !bytes.Equal(f.data, data) {
		t.Fatal("resumed file differs")
	}
	if n, _ := p.blocksSent(0); n != 200_000 {
		t.Errorf("%d bytes sent, want 200000", n)
	}
	if first.Done < 100_000 {
		t.Errorf("progress does not start at the offset: %+v", first)
	}
}

func TestUploadRemoteError(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.failWrite = "Permission denied (os error 13)"
	c := p.start(true)
	src := filepath.Join(t.TempDir(), "d")
	write(t, filepath.Join(src, "a.bin"), noise(600_000))
	write(t, filepath.Join(src, "b.bin"), noise(10))
	var re *RemoteError
	err := c.Upload(testCtx(t), src, "/root/d", TransferOptions{Recursive: true})
	if !errors.As(err, &re) || re.Path != "/root/d/a.bin" || !strings.Contains(re.Msg, "Permission denied") {
		t.Fatalf("got %v", err)
	}
	p.waitCancelled(1)
	if _, err := os.Stat(filepath.Join(src, "nope")); err == nil {
		t.Fatal("unexpected")
	}
	if err := c.Upload(testCtx(t), filepath.Join(src, "nope"), "/x", TransferOptions{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing source: %v", err)
	}
}

func TestUploadUnconfirmed(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.script = func(m *pb.Message) bool { return m.GetFileResponse().GetDone() != nil }
	c := p.start(true)
	c.timeout = 100 * time.Millisecond
	src := filepath.Join(t.TempDir(), "a")
	write(t, src, text(10))
	if err := c.Upload(testCtx(t), src, "/srv/a", TransferOptions{}); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("got %v", err)
	}
}

func TestUploadCancel(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	c := p.start(true)
	src := filepath.Join(t.TempDir(), "a.bin")
	write(t, src, noise(1_000_000))
	// Before any data...
	ctx, cancel := context.WithCancel(testCtx(t))
	err := c.Upload(ctx, src, "/srv/a.bin", TransferOptions{Progress: func(Progress) { cancel() }})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	p.waitCancelled(1)
	// ...and while waiting for the peer's answer to a digest.
	p.mu.Lock()
	p.script = func(m *pb.Message) bool { return m.GetFileResponse().GetDigest() != nil }
	p.mu.Unlock()
	ctx, cancel = context.WithCancel(testCtx(t))
	time.AfterFunc(50*time.Millisecond, cancel)
	if err := c.Upload(ctx, src, "/srv/a.bin", TransferOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	p.waitCancelled(2)
	if p.file("/srv/a.bin") != nil {
		t.Fatal("cancelled upload was kept")
	}
}

func TestUploadToWindows(t *testing.T) {
	p := newFakePeer(t, true, `C:\Users\u`)
	c := p.start(true)
	src := filepath.Join(t.TempDir(), "proj")
	write(t, filepath.Join(src, "sub", "b.txt"), text(10))
	write(t, filepath.Join(src, "a.txt"), text(20))
	if err := c.Upload(testCtx(t), src, `~\Desktop\`, TransferOptions{Recursive: true}); err != nil {
		t.Fatal(err)
	}
	r := receive(p)
	if r.GetPath() != `C:\Users\u\Desktop\proj` || r.GetFiles()[0].GetName() != "a.txt" || r.GetFiles()[1].GetName() != `sub\b.txt` {
		t.Fatalf("announcement: %v", r)
	}
	if p.file(`C:\Users\u\Desktop\proj\sub\b.txt`) == nil {
		t.Fatal("not written")
	}
}

// ----------------------------------------------------------------- session

func TestPermissionRevoked(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.put("/srv/a.bin", noise(5000), mtime)
	p.chunk = 1000
	p.hold = true
	c := p.start(true)
	revoke := &pb.Message{Union: &pb.Message_Misc{Misc: &pb.Misc{Union: &pb.Misc_PermissionInfo{
		PermissionInfo: &pb.PermissionInfo{Permission: pb.PermissionInfo_File, Enabled: false},
	}}}}
	// In the middle of a download...
	var once sync.Once
	err := c.Download(testCtx(t), "/srv/a.bin", t.TempDir(), TransferOptions{Progress: func(pr Progress) {
		if pr.Name != "" {
			once.Do(func() { go p.emit(revoke) })
		}
	}})
	if !errors.Is(err, ErrPermission) {
		t.Fatalf("got %v", err)
	}
	// ...and for everything after it.
	if _, err := c.List(testCtx(t), "", false); !errors.Is(err, ErrPermission) {
		t.Fatalf("got %v", err)
	}
}

func TestSessionLost(t *testing.T) {
	p := newFakePeer(t, false, "/home/u")
	p.put("/srv/a.bin", noise(5000), mtime)
	p.chunk = 1000
	p.hold = true
	c := p.start(true)
	err := c.Download(testCtx(t), "/srv/a.bin", t.TempDir(), TransferOptions{Progress: func(pr Progress) {
		if pr.Name != "" {
			p.Close("")
		}
	}})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
	if _, err := c.List(testCtx(t), "", false); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
	c.Close() // twice is fine
	c.Close()
}

func TestWindowsSessionIsSelected(t *testing.T) {
	p := newFakePeer(t, true, `C:\Users\u`)
	c := newClient(p, &pb.PeerInfo{Platform: "Windows", WindowsSessions: &pb.WindowsSessions{
		Sessions: []*pb.WindowsSession{{Sid: 1}, {Sid: 3}}, CurrentSid: 3,
	}})
	defer c.Close()
	m := <-p.in
	if m.GetMisc().GetSelectedSid() != 3 {
		t.Fatalf("first message: %v", m)
	}
}
