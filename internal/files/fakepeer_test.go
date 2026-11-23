package files

import (
	"net"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/bropines/rdcli/internal/pb"
)

// fakePeer is a controlled side with a file system in memory, speaking the
// protocol the way connection.rs / ui_cm_interface.rs / fs.rs do. It is the
// link of the client under test.
type fakePeer struct {
	t       *testing.T
	windows bool
	home    string
	chunk   int

	in     chan *pb.Message // client to peer
	out    chan *pb.Message // peer to client
	closed chan struct{}
	once   sync.Once
	enc    *zstd.Encoder
	dec    *zstd.Decoder

	mu        sync.Mutex
	files     map[string]*fakeFile
	dirs      map[string]bool
	partials  map[string][]byte // "<file>.download" left by a dropped upload
	log       []*pb.Message     // everything the client sent
	cancelled []int32
	reads     map[int32]*fakeRead
	writes    map[int32]*fakeWrite

	// script sees every message first; true means it handled it.
	script func(m *pb.Message) bool
	// hold stops a read job after its first block.
	hold bool
	// failWrite answers data blocks with this error.
	failWrite string
	// noEmptyDirs leaves ReadEmptyDirs unanswered, like an old peer.
	noEmptyDirs bool
}

type fakeFile struct {
	data  []byte
	mtime uint64
}

type fakeRead struct {
	id      int32
	path    string
	entries []*pb.FileEntry
	n       int
	skipped int
}

type fakeWrite struct {
	id    int32
	path  string
	files []*pb.FileEntry
	cur   int
	buf   []byte
}

func newFakePeer(t *testing.T, windows bool, home string) *fakePeer {
	enc, _ := zstd.NewWriter(nil)
	dec, _ := zstd.NewReader(nil)
	p := &fakePeer{
		t: t, windows: windows, home: home, chunk: blockSize,
		in: make(chan *pb.Message, 1<<14), out: make(chan *pb.Message, 8), closed: make(chan struct{}),
		enc: enc, dec: dec,
		files: map[string]*fakeFile{}, dirs: map[string]bool{}, partials: map[string][]byte{},
		reads: map[int32]*fakeRead{}, writes: map[int32]*fakeWrite{},
	}
	p.mkdirAll(home)
	return p
}

// start runs the peer and returns a client connected to it. Like a real
// peer it first sends the listing of the home folder, unasked.
func (p *fakePeer) start(initialListing bool) *Client {
	platform := "Linux"
	if p.windows {
		platform = "Windows"
	}
	c := newClient(p, &pb.PeerInfo{Platform: platform, Version: "1.4.3", Username: "u"})
	c.emptyWait = 300 * time.Millisecond
	if initialListing {
		p.mu.Lock()
		p.readDir("")
		p.mu.Unlock()
	} else {
		c.initialWait = 30 * time.Millisecond
	}
	go func() {
		for {
			select {
			case m := <-p.in:
				p.mu.Lock()
				p.log = append(p.log, m)
				if p.script == nil || !p.script(m) {
					p.handle(m)
				}
				p.mu.Unlock()
			case <-p.closed:
				return
			}
		}
	}()
	p.t.Cleanup(c.Close)
	return c
}

// ------------------------------------------------------------------ link

func (p *fakePeer) Send(m *pb.Message) error {
	select {
	case <-p.closed:
		return net.ErrClosed
	default:
	}
	select {
	case p.in <- proto.Clone(m).(*pb.Message):
		return nil
	default:
		p.t.Error("fake peer: inbox overflow")
		return net.ErrClosed
	}
}

func (p *fakePeer) Recv() (*pb.Message, error) {
	select {
	case m := <-p.out:
		return m, nil
	case <-p.closed:
		return nil, net.ErrClosed
	}
}

func (p *fakePeer) Close(string) { p.once.Do(func() { close(p.closed) }) }

func (p *fakePeer) emit(m *pb.Message) {
	select {
	case p.out <- m:
	case <-p.closed:
	}
}

func (p *fakePeer) emitResponse(r *pb.FileResponse) {
	p.emit(&pb.Message{Union: &pb.Message_FileResponse{FileResponse: r}})
}

func (p *fakePeer) emitError(id int32, text string, fileNum int32) {
	p.emitResponse(&pb.FileResponse{Union: &pb.FileResponse_Error{Error: &pb.FileTransferError{Id: id, Error: text, FileNum: fileNum}}})
}

func (p *fakePeer) emitDone(id, fileNum int32) {
	p.emitResponse(&pb.FileResponse{Union: &pb.FileResponse_Done{Done: &pb.FileTransferDone{Id: id, FileNum: fileNum}}})
}

func (p *fakePeer) emitDir(id int32, path string, entries []*pb.FileEntry) {
	p.emitResponse(&pb.FileResponse{Union: &pb.FileResponse_Dir{Dir: &pb.FileDirectory{Id: id, Path: path, Entries: entries}}})
}

func (p *fakePeer) emitDigest(d *pb.FileTransferDigest) {
	p.emitResponse(&pb.FileResponse{Union: &pb.FileResponse_Digest{Digest: d}})
}

func (p *fakePeer) emitBlock(id int32, fileNum int, data []byte) {
	b := &pb.FileTransferBlock{Id: id, FileNum: int32(fileNum), Data: data}
	if z := p.enc.EncodeAll(data, nil); len(data) > 0 && len(z) < len(data) {
		b.Data, b.Compressed = z, true
	}
	p.emitResponse(&pb.FileResponse{Union: &pb.FileResponse_Block{Block: b}})
}

// ----------------------------------------------------------- file system

func (p *fakePeer) mkdirAll(dir string) {
	for d := dir; d != "/" && d != "" && !p.dirs[d]; d = parentRemote(d, p.windows) {
		p.dirs[d] = true
	}
}

func (p *fakePeer) put(path string, data []byte, mtime uint64) {
	p.mkdirAll(parentRemote(path, p.windows))
	p.files[path] = &fakeFile{data: data, mtime: mtime}
}

func (p *fakePeer) file(path string) *fakeFile {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.files[path]
}

func (p *fakePeer) hasDir(path string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dirs[path]
}

func (p *fakePeer) children(dir string) []*pb.FileEntry {
	var out []*pb.FileEntry
	for path, f := range p.files {
		if parentRemote(path, p.windows) == dir {
			out = append(out, &pb.FileEntry{EntryType: pb.FileType_File, Name: baseRemote(path, p.windows), Size: uint64(len(f.data)), ModifiedTime: f.mtime})
		}
	}
	for path := range p.dirs {
		if path != dir && parentRemote(path, p.windows) == dir {
			out = append(out, &pb.FileEntry{EntryType: pb.FileType_Dir, Name: baseRemote(path, p.windows)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// recursive is fs.rs get_recursive_files: the files below dir, named by
// their path below it.
func (p *fakePeer) recursive(dir string) []*pb.FileEntry {
	var out []*pb.FileEntry
	for path, f := range p.files {
		if rel, ok := relRemote(dir, path, p.windows); ok && rel != "" {
			out = append(out, &pb.FileEntry{EntryType: pb.FileType_File, Name: rel, Size: uint64(len(f.data)), ModifiedTime: f.mtime})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (p *fakePeer) readDir(path string) {
	if path == "" {
		path = p.home
	}
	if !p.dirs[path] {
		p.emitError(0, "No such file or directory (os error 2)", -1)
		return
	}
	p.emitDir(0, path, p.children(path))
}

// --------------------------------------------------------------- protocol

func (p *fakePeer) handle(m *pb.Message) {
	switch u := m.Union.(type) {
	case *pb.Message_FileAction:
		switch a := u.FileAction.Union.(type) {
		case *pb.FileAction_ReadDir:
			p.readDir(a.ReadDir.GetPath())
		case *pb.FileAction_ReadEmptyDirs:
			if p.noEmptyDirs {
				return
			}
			root := a.ReadEmptyDirs.GetPath()
			var fds []*pb.FileDirectory
			for d := range p.dirs {
				if _, ok := relRemote(root, d, p.windows); ok && len(p.children(d)) == 0 {
					fds = append(fds, &pb.FileDirectory{Path: d})
				}
			}
			p.emitResponse(&pb.FileResponse{Union: &pb.FileResponse_EmptyDirs{EmptyDirs: &pb.ReadEmptyDirsResponse{Path: root, EmptyDirs: fds}}})
		case *pb.FileAction_Create:
			p.mkdirAll(a.Create.GetPath())
			p.emitDone(a.Create.GetId(), 0)
		case *pb.FileAction_Cancel:
			id := a.Cancel.GetId()
			delete(p.reads, id)
			delete(p.writes, id)
			p.cancelled = append(p.cancelled, id)
		case *pb.FileAction_Send:
			p.startRead(a.Send)
		case *pb.FileAction_Receive:
			r := a.Receive
			p.writes[r.GetId()] = &fakeWrite{id: r.GetId(), path: r.GetPath(), files: r.GetFiles(), cur: -1}
		case *pb.FileAction_SendConfirm:
			sc := a.SendConfirm
			if j := p.reads[sc.GetId()]; j != nil {
				p.confirmRead(j, sc)
			} else if w := p.writes[sc.GetId()]; w != nil {
				// fs.rs confirm: an offset only counts for the file the
				// write job is at.
				if off := sc.GetOffsetBlk(); off > 0 && int(sc.GetFileNum()) == max(w.cur, 0) {
					w.cur = int(sc.GetFileNum())
					w.buf = slices.Clone(p.partials[w.target(p, w.cur)][:off])
				}
			}
		}
	case *pb.Message_FileResponse:
		switch r := u.FileResponse.Union.(type) {
		case *pb.FileResponse_Digest:
			p.checkDigest(r.Digest)
		case *pb.FileResponse_Block:
			p.writeBlock(r.Block)
		case *pb.FileResponse_Done:
			if w := p.writes[r.Done.GetId()]; w != nil {
				p.commit(w)
				delete(p.writes, w.id)
				p.emitDone(w.id, r.Done.GetFileNum())
			}
		case *pb.FileResponse_Error:
			if w := p.writes[r.Error.GetId()]; w != nil {
				delete(p.writes, w.id)
				p.emitError(w.id, r.Error.GetError(), r.Error.GetFileNum())
			}
		}
	}
}

func (p *fakePeer) startRead(s *pb.FileTransferSendRequest) {
	id, path := s.GetId(), s.GetPath()
	var entries []*pb.FileEntry
	switch {
	case p.files[path] != nil:
		f := p.files[path]
		entries = []*pb.FileEntry{{EntryType: pb.FileType_File, Size: uint64(len(f.data)), ModifiedTime: f.mtime}}
	case p.dirs[path]:
		entries = p.recursive(path)
	default:
		p.emitError(id, "Not exists", 0)
		return
	}
	j := &fakeRead{id: id, path: path, entries: entries}
	p.reads[id] = j
	p.emitDir(id, path, entries)
	p.advanceRead(j)
}

func (p *fakePeer) readTarget(j *fakeRead) *fakeFile {
	if name := j.entries[j.n].GetName(); name != "" {
		return p.files[joinRemote(j.path, name, p.windows)]
	}
	return p.files[j.path]
}

// advanceRead announces the next file with its digest, or ends the job.
func (p *fakePeer) advanceRead(j *fakeRead) {
	if j.n >= len(j.entries) {
		delete(p.reads, j.id)
		if len(j.entries) == 1 && j.skipped == 1 {
			p.emitError(j.id, "skipped", int32(j.n))
		} else {
			p.emitDone(j.id, int32(j.n))
		}
		return
	}
	f := p.readTarget(j)
	p.emitDigest(&pb.FileTransferDigest{Id: j.id, FileNum: int32(j.n), LastModified: f.mtime, FileSize: uint64(len(f.data))})
}

func (p *fakePeer) confirmRead(j *fakeRead, sc *pb.FileTransferSendConfirmRequest) {
	if int(sc.GetFileNum()) != j.n {
		return
	}
	if sc.GetSkip() {
		j.skipped++
		j.n++
		p.advanceRead(j)
		return
	}
	data := p.readTarget(j).data[sc.GetOffsetBlk():]
	for len(data) > 0 {
		k := min(p.chunk, len(data))
		p.emitBlock(j.id, j.n, data[:k])
		data = data[k:]
		if p.hold {
			return
		}
	}
	p.emitBlock(j.id, j.n, nil)
	j.n++
	p.advanceRead(j)
}

func (w *fakeWrite) target(p *fakePeer, n int) string {
	return joinRemote(w.path, w.files[n].GetName(), p.windows)
}

// checkDigest is ui_cm_interface.rs CheckDigest.
func (p *fakePeer) checkDigest(d *pb.FileTransferDigest) {
	w := p.writes[d.GetId()]
	if w == nil || int(d.GetFileNum()) >= len(w.files) {
		return
	}
	target := w.target(p, int(d.GetFileNum()))
	if part := p.partials[target]; d.GetIsResume() && len(part) > 0 {
		p.emitDigest(&pb.FileTransferDigest{
			Id: w.id, FileNum: d.GetFileNum(), LastModified: d.GetLastModified(), FileSize: d.GetFileSize(),
			IsIdentical: true, TransferredSize: uint64(len(part)),
		})
		return
	}
	if f := p.files[target]; f != nil {
		p.emitDigest(&pb.FileTransferDigest{
			Id: w.id, FileNum: d.GetFileNum(), LastModified: f.mtime, FileSize: uint64(len(f.data)), IsUpload: true,
			IsIdentical: f.mtime == d.GetLastModified() && uint64(len(f.data)) == d.GetFileSize(),
		})
		return
	}
	p.emit(&pb.Message{Union: &pb.Message_FileAction{FileAction: &pb.FileAction{Union: &pb.FileAction_SendConfirm{
		SendConfirm: &pb.FileTransferSendConfirmRequest{Id: w.id, FileNum: d.GetFileNum(), Union: &pb.FileTransferSendConfirmRequest_OffsetBlk{}},
	}}}})
}

func (p *fakePeer) writeBlock(b *pb.FileTransferBlock) {
	w := p.writes[b.GetId()]
	if w == nil {
		return
	}
	if p.failWrite != "" {
		delete(p.writes, w.id)
		p.emitError(w.id, p.failWrite, b.GetFileNum())
		return
	}
	if n := int(b.GetFileNum()); n != w.cur {
		p.commit(w)
		w.cur, w.buf = n, []byte{}
	}
	data := b.GetData()
	if b.GetCompressed() {
		var err error
		if data, err = p.dec.DecodeAll(data, nil); err != nil {
			p.t.Errorf("fake peer: bad compressed block: %v", err)
		}
	}
	w.buf = append(w.buf, data...)
}

// commit is fs.rs modify_time: the finished file gets its name and time.
func (p *fakePeer) commit(w *fakeWrite) {
	if w.cur < 0 || w.buf == nil {
		return
	}
	target := w.target(p, w.cur)
	p.put(target, w.buf, w.files[w.cur].GetModifiedTime())
	delete(p.partials, target)
	w.buf = nil
}

// ---------------------------------------------------------------- queries

// sent returns what the client sent so far, after the peer handled it.
func (p *fakePeer) sent() []*pb.Message {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.log)
}

// waitFor polls until cond holds.
func (p *fakePeer) waitFor(what string, cond func() bool) {
	p.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			p.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (p *fakePeer) waitCancelled(n int) {
	p.t.Helper()
	p.waitFor("the job's cancellation", func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.cancelled) >= n
	})
}

// blocksSent sums the data the client uploaded for one file number.
func (p *fakePeer) blocksSent(fileNum int) (bytes int, blocks int) {
	for _, m := range p.sent() {
		if b := m.GetFileResponse().GetBlock(); b != nil && int(b.GetFileNum()) == fileNum && len(b.GetData()) > 0 {
			data := b.GetData()
			if b.GetCompressed() {
				data, _ = p.dec.DecodeAll(data, nil)
			}
			bytes += len(data)
			blocks++
		}
	}
	return bytes, blocks
}
