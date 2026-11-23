// Package files transfers files over a logged-in FILE_TRANSFER session:
// remote listings, downloads and uploads of files and folders.
//
// The protocol is the one RustDesk's file manager speaks (FileAction from
// the controller, FileResponse from the device, and the two swapped for the
// data of an upload). The behaviour mirrors rdweb's src/files, which is
// proven against real peers, and upstream's libs/base/src/fs.rs.
package files

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/bropines/rdcli/internal/pb"
	"github.com/bropines/rdcli/internal/peer"
)

const (
	// requestTimeout bounds the wait for an answer to one request.
	requestTimeout = 30 * time.Second
	// idleTimeout bounds the silence inside a running download.
	idleTimeout = 2 * time.Minute
	// initialListingWait is how long the first listing request waits for
	// the listing peers send unasked after login.
	initialListingWait = 10 * time.Second
	// emptyDirsWait bounds the wait for the list of empty folders, which
	// older peers never answer.
	emptyDirsWait = 5 * time.Second
	// blockSize is how the desktop client reads files (fs.rs BUF_SIZE).
	blockSize = 128 << 10
	// maxBlockSize caps one block, compressed and inflated.
	maxBlockSize = 4 << 20

	// Peers from this version announce existing files (digest dialogue).
	digestSince = 1_001_010
	// Peers from this version can continue a partial upload.
	resumeSince = 1_004_002
)

var (
	// ErrIsDirectory: the source is a folder and Recursive is not set.
	ErrIsDirectory = errors.New("is a directory (not copied without Recursive)")
	// ErrClosed: the client or the session was closed.
	ErrClosed = errors.New("file transfer session closed")
	// ErrTimeout: the peer did not answer in time.
	ErrTimeout = errors.New("the remote device did not answer")
	// ErrUnconfirmed: everything was uploaded but the peer did not
	// acknowledge the end of the job.
	ErrUnconfirmed = errors.New("upload sent, but the remote device did not confirm it")
	// ErrPermission: file transfer is switched off on the remote side.
	ErrPermission = errors.New("file transfer is disabled on the remote side")
)

// RemoteError is a failure reported by the peer.
type RemoteError struct {
	Op   string // "list", "download", "upload", "mkdir"
	Path string
	Msg  string // the peer's text (an io::Error string, or one of its own)
}

func (e *RemoteError) Error() string {
	msg := e.Msg
	if strings.Contains(msg, "one-way-file-transfer") {
		msg = "the device allows file transfer in the other direction only"
	}
	return fmt.Sprintf("%s %s: %s", e.Op, e.Path, msg)
}

// Entry is one item of a remote folder.
type Entry struct {
	Name string
	// IsDir is set for folders, links to folders and drives.
	IsDir bool
	// IsDrive is set for the drives a Windows peer lists at "/".
	IsDrive   bool
	IsSymlink bool
	IsHidden  bool
	// Size in bytes (0 for folders and links).
	Size int64
	// ModTime is zero when the peer did not report one.
	ModTime time.Time
}

// Progress describes a running transfer.
type Progress struct {
	// Name is the current file, "/"-separated below the transfer's root
	// (empty between files).
	Name                string
	FileDone, FileTotal int64
	// Done and Total count the bytes of the whole transfer; skipped files
	// are taken out of Total.
	Done, Total int64
	// Files is the number of files in the transfer.
	Files, FilesDone, FilesSkipped int
}

// TransferOptions tunes Download and Upload.
type TransferOptions struct {
	// Recursive allows folders; without it a folder fails with
	// ErrIsDirectory, like scp.
	Recursive bool
	// ShowHidden includes hidden files of a folder (the peer decides what
	// is hidden for downloads; uploads leave out dot files without it).
	ShowHidden bool
	// SkipExisting leaves files alone that already exist at the
	// destination. The default is to overwrite.
	SkipExisting bool
	// Resume skips files the destination already has with the same size
	// and modification time, and continues a partial copy left by an
	// interrupted transfer where the protocol allows it.
	Resume bool
	// Progress is called from the transferring goroutine.
	Progress func(Progress)
}

// link is what the client needs from a peer.Session.
type link interface {
	Send(*pb.Message) error
	Recv() (*pb.Message, error)
	Close(reason string)
}

// job routes the peer's messages for one job id to the goroutine running it.
type job struct {
	id   int32
	in   chan any
	done chan struct{}
}

type listResult struct {
	dir *pb.FileDirectory
	err error
}

type listRequest struct {
	path string
	ch   chan listResult
}

// Client drives one FILE_TRANSFER session. Its methods may be called from
// several goroutines; transfers run one at a time (the peer works through
// its jobs one by one as well).
type Client struct {
	l       link
	windows bool
	version int64

	timeout     time.Duration
	idle        time.Duration
	initialWait time.Duration
	emptyWait   time.Duration
	goos        string
	debugf      func(string, ...any)

	enc *zstd.Encoder
	dec *zstd.Decoder

	transferSem chan struct{}
	listSem     chan struct{}
	dead        chan struct{}
	readerDone  chan struct{}

	mu          sync.Mutex
	err         error
	denied      bool
	nextID      int32
	jobs        map[int32]*job
	listing     *listRequest
	stale       int // listings given up on whose answers may still arrive
	initialSeen bool
	initial     chan struct{}
	home        string
	emptyDirs   chan *pb.ReadEmptyDirsResponse
}

// LoginFields returns the LoginRequest fields of a file transfer session.
// dir is the folder the peer lists first; empty means the remote user's
// home (peers also fall back to it when dir does not exist).
func LoginFields(dir string, showHidden bool) func(*pb.LoginRequest) {
	return func(lr *pb.LoginRequest) {
		lr.Union = &pb.LoginRequest_FileTransfer{FileTransfer: &pb.FileTransfer{Dir: dir, ShowHidden: showHidden}}
	}
}

// LoginErrorCode classifies a file transfer login refusal.
func LoginErrorCode(e string) peer.Code {
	if strings.Contains(strings.ToLower(e), "no permission") {
		return peer.CodePermissionDenied
	}
	return peer.CodeLogin
}

// New starts the client on a session logged in with ConnType FILE_TRANSFER
// and LoginFields. It owns s.Recv from here on.
// debugf, if not nil, traces listings (rdcli -v).
func New(s *peer.Session, debugf func(string, ...any)) *Client {
	return newClientDebug(s, s.PeerInfo, debugf)
}

func newClient(l link, pi *pb.PeerInfo) *Client { return newClientDebug(l, pi, nil) }

func newClientDebug(l link, pi *pb.PeerInfo, debugf func(string, ...any)) *Client {
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
	dec, _ := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxBlockSize))
	c := &Client{
		l:           l,
		windows:     strings.HasPrefix(strings.ToLower(pi.GetPlatform()), "win"),
		version:     versionNumber(pi.GetVersion()),
		timeout:     requestTimeout,
		idle:        idleTimeout,
		initialWait: initialListingWait,
		emptyWait:   emptyDirsWait,
		goos:        localOS,
		debugf:      debugf,
		enc:         enc,
		dec:         dec,
		transferSem: make(chan struct{}, 1),
		listSem:     make(chan struct{}, 1),
		dead:        make(chan struct{}),
		readerDone:  make(chan struct{}),
		nextID:      1,
		jobs:        map[int32]*job{},
		initial:     make(chan struct{}),
	}
	// A Windows host with several user sessions lists nothing until we pick
	// one (connection.rs delayed_read_dir); stay in the one it runs in.
	if ws := pi.GetWindowsSessions(); len(ws.GetSessions()) > 0 {
		l.Send(&pb.Message{Union: &pb.Message_Misc{Misc: &pb.Misc{Union: &pb.Misc_SelectedSid{SelectedSid: ws.GetCurrentSid()}}}})
	}
	go c.readLoop()
	return c
}

// Close ends the client and closes the session under it.
func (c *Client) Close() {
	c.fail(ErrClosed)
	c.l.Close("")
	<-c.readerDone
}

// Windows reports whether the peer uses Windows paths ("\" and drives).
func (c *Client) Windows() bool { return c.windows }

// Join joins a remote folder and a name with the peer's separator.
func (c *Client) Join(dir, name string) string { return joinRemote(dir, name, c.windows) }

// Parent is the folder above a remote path; on Windows the parent of a
// drive root is the drive list "/".
func (c *Client) Parent(p string) string { return parentRemote(p, c.windows) }

// Base is the last component of a remote path.
func (c *Client) Base(p string) string { return baseRemote(p, c.windows) }

// ------------------------------------------------------------- read loop

func (c *Client) readLoop() {
	defer close(c.readerDone)
	for {
		m, err := c.l.Recv()
		if err != nil {
			c.fail(err)
			return
		}
		if c.debugf != nil {
			if fr, ok := m.Union.(*pb.Message_FileResponse); !ok {
				c.debugf("files: received %T", m.Union)
			} else if _, block := fr.FileResponse.Union.(*pb.FileResponse_Block); !block {
				c.debugf("files: received %T", fr.FileResponse.Union)
			}
		}
		switch u := m.Union.(type) {
		case *pb.Message_FileResponse:
			c.onResponse(u.FileResponse)
		case *pb.Message_FileAction:
			// The peer answers the digests of an upload with a send
			// confirmation, which is a FileAction.
			if sc := u.FileAction.GetSendConfirm(); sc != nil {
				c.deliver(sc.GetId(), sc)
			}
		case *pb.Message_Misc:
			if p := u.Misc.GetPermissionInfo(); p != nil && p.GetPermission() == pb.PermissionInfo_File {
				c.onPermission(p.GetEnabled())
			}
		}
	}
}

func (c *Client) onResponse(r *pb.FileResponse) {
	switch u := r.Union.(type) {
	case *pb.FileResponse_Dir:
		// Listings carry no id; the file list of a job carries the job's.
		if id := u.Dir.GetId(); id != 0 {
			c.deliver(id, u.Dir)
		} else {
			c.onListing(u.Dir, nil)
		}
	case *pb.FileResponse_Block:
		c.deliver(u.Block.GetId(), u.Block)
	case *pb.FileResponse_Digest:
		c.deliver(u.Digest.GetId(), u.Digest)
	case *pb.FileResponse_Done:
		c.deliver(u.Done.GetId(), u.Done)
	case *pb.FileResponse_Error:
		if id := u.Error.GetId(); id != 0 {
			c.deliver(id, u.Error)
		} else {
			c.onListing(nil, u.Error)
		}
	case *pb.FileResponse_EmptyDirs:
		c.mu.Lock()
		ch := c.emptyDirs
		c.mu.Unlock()
		if ch != nil {
			select {
			case ch <- u.EmptyDirs:
			default:
			}
		}
	}
}

// deliver hands a message to its job; a slow job holds back the read loop
// (and with it the peer), which is the flow control of a download.
func (c *Client) deliver(id int32, m any) {
	c.mu.Lock()
	j := c.jobs[id]
	c.mu.Unlock()
	if j == nil {
		return
	}
	select {
	case j.in <- m:
	case <-j.done:
	case <-c.dead:
	}
}

// onListing matches a listing (or its error) to the request it answers.
// Peers answer listings in order, the first one being the listing they
// send unasked after login.
func (c *Client) onListing(fd *pb.FileDirectory, e *pb.FileTransferError) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.debugf != nil {
		if fd != nil {
			c.debugf("files: listing of %q (%d entries); initial seen %v, pending %v, stale %d", fd.GetPath(), len(fd.GetEntries()), c.initialSeen, c.listing != nil, c.stale)
		} else {
			c.debugf("files: listing error %q; initial seen %v, pending %v, stale %d", e.GetError(), c.initialSeen, c.listing != nil, c.stale)
		}
	}
	if !c.initialSeen {
		c.initialSeen = true
		close(c.initial)
		return
	}
	r := c.listing
	if r == nil {
		if c.stale > 0 {
			c.stale--
		}
		return
	}
	if c.stale > 0 {
		// An answer to a listing we gave up on may come first; tell them
		// apart by the path where there is one.
		want := r.path
		if want == "" {
			want = c.home
		}
		if fd == nil || want != "" && !samePath(want, fd.GetPath(), c.windows) {
			c.stale--
			return
		}
	}
	c.listing = nil
	if fd == nil {
		r.ch <- listResult{err: &RemoteError{Op: "list", Path: displayPath(r.path), Msg: e.GetError()}}
		return
	}
	if r.path == "" {
		c.home = fd.GetPath()
	}
	r.ch <- listResult{dir: fd}
}

func (c *Client) onPermission(enabled bool) {
	c.mu.Lock()
	was := c.denied
	c.denied = !enabled
	var jobs []*job
	if !enabled && !was {
		for _, j := range c.jobs {
			jobs = append(jobs, j)
		}
	}
	c.mu.Unlock()
	for _, j := range jobs {
		select {
		case j.in <- ErrPermission:
		case <-j.done:
		case <-c.dead:
		}
	}
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
		close(c.dead)
	}
}

func (c *Client) deadErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if errors.Is(c.err, ErrClosed) {
		return ErrClosed
	}
	return fmt.Errorf("%w: %w", ErrClosed, c.err)
}

// check refuses new work on a dead or forbidden session.
func (c *Client) check() error {
	select {
	case <-c.dead:
		return c.deadErr()
	default:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.denied {
		return ErrPermission
	}
	return nil
}

func (c *Client) acquire(ctx context.Context, sem chan struct{}) error {
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.dead:
		return c.deadErr()
	}
}

// ------------------------------------------------------------------ jobs

func (c *Client) newJob() *job {
	c.mu.Lock()
	defer c.mu.Unlock()
	j := &job{id: c.nextID, in: make(chan any, 32), done: make(chan struct{})}
	if c.nextID == 1<<31-1 {
		c.nextID = 1
	} else {
		c.nextID++
	}
	c.jobs[j.id] = j
	return j
}

func (c *Client) endJob(j *job) {
	c.mu.Lock()
	delete(c.jobs, j.id)
	c.mu.Unlock()
	close(j.done)
}

// next waits for the job's next message.
func (c *Client) next(ctx context.Context, j *job, wait time.Duration) (any, error) {
	select {
	case m := <-j.in:
		return m, nil
	default:
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case m := <-j.in:
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.dead:
		return nil, c.deadErr()
	case <-t.C:
		return nil, ErrTimeout
	}
}

// poll returns a message that is already waiting, or nil.
func (j *job) poll() any {
	select {
	case m := <-j.in:
		return m
	default:
		return nil
	}
}

func (c *Client) send(m *pb.Message) error {
	if err := c.l.Send(m); err != nil {
		select {
		case <-c.dead:
			return c.deadErr()
		default:
		}
		return fmt.Errorf("%w: %w", ErrClosed, err)
	}
	return nil
}

func (c *Client) action(a *pb.FileAction) error {
	return c.send(&pb.Message{Union: &pb.Message_FileAction{FileAction: a}})
}

func (c *Client) response(r *pb.FileResponse) error {
	return c.send(&pb.Message{Union: &pb.Message_FileResponse{FileResponse: r}})
}

// cancel lets the peer drop the job (and the partial file of an upload).
func (c *Client) cancel(id int32) {
	select {
	case <-c.dead:
		return
	default:
	}
	c.action(&pb.FileAction{Union: &pb.FileAction_Cancel{Cancel: &pb.FileTransferCancel{Id: id}}})
}

func (c *Client) confirm(id int32, fileNum int, skip bool, offset uint32) error {
	r := &pb.FileTransferSendConfirmRequest{Id: id, FileNum: int32(fileNum)}
	if skip {
		r.Union = &pb.FileTransferSendConfirmRequest_Skip{Skip: true}
	} else {
		r.Union = &pb.FileTransferSendConfirmRequest_OffsetBlk{OffsetBlk: offset}
	}
	return c.action(&pb.FileAction{Union: &pb.FileAction_SendConfirm{SendConfirm: r}})
}

// -------------------------------------------------------------- listings

func displayPath(p string) string {
	if p == "" {
		return "~"
	}
	return p
}

// expand resolves "~/x" against the remote home. A bare "~" becomes "",
// which peers answer with the home folder.
func (c *Client) expand(ctx context.Context, p string) (string, error) {
	if p == "~" {
		return "", nil
	}
	if strings.HasPrefix(p, "~/") || c.windows && strings.HasPrefix(p, `~\`) {
		home, err := c.Home(ctx)
		if err != nil {
			return "", err
		}
		rest := p[2:]
		if c.windows {
			rest = strings.ReplaceAll(rest, "/", `\`)
		}
		return joinRemote(home, strings.TrimLeft(rest, `/\`), c.windows), nil
	}
	return p, nil
}

// resolve is expand for transfers, which need the home folder spelled out.
func (c *Client) resolve(ctx context.Context, p string) (string, error) {
	if p == "" || p == "~" {
		return c.Home(ctx)
	}
	p, err := c.expand(ctx, p)
	if err != nil {
		return "", err
	}
	// "dir/" is "dir", but "/" and "C:\" stay what they are.
	if t := trimRemote(p, c.windows); t != "" && !isDrive(t) {
		p = t
	}
	return p, nil
}

// Home returns the remote user's home folder. The protocol has no field
// for it: a listing of "" is answered with the home folder's path.
func (c *Client) Home(ctx context.Context) (string, error) {
	c.mu.Lock()
	home := c.home
	c.mu.Unlock()
	if home != "" {
		return home, nil
	}
	fd, err := c.readDir(ctx, "", false)
	if err != nil {
		return "", err
	}
	return fd.GetPath(), nil
}

// List lists a remote folder. "" and "~" list the remote user's home, and
// on Windows peers "/" lists the drives.
func (c *Client) List(ctx context.Context, remoteDir string, showHidden bool) ([]Entry, error) {
	dir, err := c.expand(ctx, remoteDir)
	if err != nil {
		return nil, err
	}
	fd, err := c.readDir(ctx, dir, showHidden)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(fd.GetEntries()))
	for _, e := range fd.GetEntries() {
		out = append(out, toEntry(e))
	}
	return out, nil
}

func toEntry(e *pb.FileEntry) Entry {
	t := e.GetEntryType()
	en := Entry{
		Name:      e.GetName(),
		IsDir:     t == pb.FileType_Dir || t == pb.FileType_DirLink || t == pb.FileType_DirDrive,
		IsDrive:   t == pb.FileType_DirDrive,
		IsSymlink: t == pb.FileType_DirLink || t == pb.FileType_FileLink,
		IsHidden:  e.GetIsHidden(),
		Size:      int64(e.GetSize()),
	}
	if mt := e.GetModifiedTime(); mt != 0 {
		en.ModTime = time.Unix(int64(mt), 0)
	}
	return en
}

// readDir sends one ReadDir and waits for its answer. Listings have no id
// on the wire, so they are serialized.
func (c *Client) readDir(ctx context.Context, path string, showHidden bool) (*pb.FileDirectory, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if err := c.acquire(ctx, c.listSem); err != nil {
		return nil, err
	}
	defer func() { <-c.listSem }()
	if err := c.waitInitial(ctx); err != nil {
		return nil, err
	}
	r := &listRequest{path: path, ch: make(chan listResult, 1)}
	c.mu.Lock()
	c.listing = r
	c.mu.Unlock()
	giveUp := func() {
		c.mu.Lock()
		if c.listing == r {
			c.listing = nil
			c.stale++
		}
		c.mu.Unlock()
	}
	if c.debugf != nil {
		c.debugf("files: list %q", path)
	}
	err := c.action(&pb.FileAction{Union: &pb.FileAction_ReadDir{ReadDir: &pb.ReadDir{Path: path, IncludeHidden: showHidden}}})
	if err != nil {
		giveUp()
		return nil, err
	}
	t := time.NewTimer(c.timeout)
	defer t.Stop()
	select {
	case res := <-r.ch:
		return res.dir, res.err
	case <-ctx.Done():
		giveUp()
		return nil, ctx.Err()
	case <-c.dead:
		return nil, c.deadErr()
	case <-t.C:
		giveUp()
		return nil, fmt.Errorf("list %s: %w", displayPath(path), ErrTimeout)
	}
}

// waitInitial lets the listing the peer sends after login pass, so that it
// is not taken for an answer.
func (c *Client) waitInitial(ctx context.Context) error {
	t := time.NewTimer(c.initialWait)
	defer t.Stop()
	select {
	case <-c.initial:
	case <-t.C:
		c.mu.Lock()
		if !c.initialSeen {
			c.initialSeen = true
			close(c.initial)
			c.stale++ // it may still come
			if c.debugf != nil {
				c.debugf("files: no listing after login within %v", c.initialWait)
			}
		}
		c.mu.Unlock()
	case <-ctx.Done():
		return ctx.Err()
	case <-c.dead:
		return c.deadErr()
	}
	return nil
}

// Mkdir creates a remote folder with its missing parents.
func (c *Client) Mkdir(ctx context.Context, remoteDir string) error {
	dir, err := c.resolve(ctx, remoteDir)
	if err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	return c.mkdir(ctx, dir)
}

func (c *Client) mkdir(ctx context.Context, dir string) error {
	j := c.newJob()
	defer c.endJob(j)
	if err := c.action(&pb.FileAction{Union: &pb.FileAction_Create{Create: &pb.FileDirCreate{Id: j.id, Path: dir}}}); err != nil {
		return err
	}
	for {
		m, err := c.next(ctx, j, c.timeout)
		if err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		switch v := m.(type) {
		case *pb.FileTransferDone:
			return nil
		case *pb.FileTransferError:
			return &RemoteError{Op: "mkdir", Path: dir, Msg: v.GetError()}
		case error:
			return v
		}
	}
}

// readEmptyDirs asks for the empty folders below path, which a transfer's
// file list does not mention. Best effort: peers do not answer on errors,
// and older ones do not know the request.
func (c *Client) readEmptyDirs(ctx context.Context, path string, showHidden bool) []string {
	ch := make(chan *pb.ReadEmptyDirsResponse, 1)
	c.mu.Lock()
	c.emptyDirs = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.emptyDirs = nil
		c.mu.Unlock()
	}()
	err := c.action(&pb.FileAction{Union: &pb.FileAction_ReadEmptyDirs{ReadEmptyDirs: &pb.ReadEmptyDirs{Path: path, IncludeHidden: showHidden}}})
	if err != nil {
		return nil
	}
	t := time.NewTimer(c.emptyWait)
	defer t.Stop()
	select {
	case r := <-ch:
		var out []string
		for _, d := range r.GetEmptyDirs() {
			out = append(out, d.GetPath())
		}
		return out
	case <-ctx.Done():
	case <-c.dead:
	case <-t.C:
	}
	return nil
}

// ------------------------------------------------------------- utilities

// inflate decompresses one block with a hard size cap.
func (c *Client) inflate(b []byte) ([]byte, error) {
	out, err := c.dec.DecodeAll(b, make([]byte, 0, blockSize))
	if err != nil {
		return nil, fmt.Errorf("bad compressed block: %w", err)
	}
	if len(out) > maxBlockSize {
		return nil, fmt.Errorf("bad compressed block: larger than %d bytes", maxBlockSize)
	}
	return out, nil
}

// progressMeter throttles progress callbacks.
type progressMeter struct {
	fn   func(Progress)
	last time.Time
}

func (p *progressMeter) report(force bool, v Progress) {
	if p.fn == nil {
		return
	}
	now := time.Now()
	if !force && now.Sub(p.last) < 100*time.Millisecond {
		return
	}
	p.last = now
	if v.Total < v.Done {
		v.Total = v.Done
	}
	p.fn(v)
}
