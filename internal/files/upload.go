package files

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/bropines/rdcli/internal/pb"
)

type upFile struct {
	rel   string // "/"-separated, below the transfer's root
	wire  string // the same with the peer's separator, as announced
	local string
	size  int64
	mtime int64
}

type upload struct {
	c     *Client
	j     *job
	opt   TransferOptions
	root  string // remote path of the announcement
	files []upFile

	cur                *upFile
	sent               int64
	done, total        int64
	filesDone, skipped int
	meter              progressMeter
}

// Upload copies a local file, or with Recursive a folder, to remotePath,
// which names the copy itself; ending it in a separator (or passing "" or
// "~") puts the item into that remote folder under its local name. Missing
// remote folders are created. remotePath may start with "~".
func (c *Client) Upload(ctx context.Context, localPath, remotePath string, opt TransferOptions) error {
	st, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	if st.IsDir() && !opt.Recursive {
		return fmt.Errorf("%s: %w", localPath, ErrIsDirectory)
	}
	if !st.IsDir() && !st.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", localPath)
	}
	into := remotePath == "" || remotePath == "~" || endsWithRemoteSep(remotePath, c.windows)
	remote, err := c.resolve(ctx, remotePath)
	if err != nil {
		return err
	}
	if into {
		abs, err := filepath.Abs(localPath)
		if err != nil {
			return err
		}
		remote = joinRemote(remote, filepath.Base(abs), c.windows)
	}
	u := &upload{c: c, opt: opt, root: remote, meter: progressMeter{fn: opt.Progress}}
	var emptyDirs []string
	if st.IsDir() {
		if emptyDirs, err = u.scan(localPath); err != nil {
			return err
		}
	} else {
		// One file is announced without a name, the path being the file
		// itself, as the desktop client does (fs.rs TransferJob::join).
		u.files = []upFile{{rel: filepath.Base(localPath), local: localPath, size: st.Size(), mtime: st.ModTime().Unix()}}
	}
	for _, f := range u.files {
		u.total += f.size
	}

	if err := c.check(); err != nil {
		return err
	}
	if err := c.acquire(ctx, c.transferSem); err != nil {
		return err
	}
	defer func() { <-c.transferSem }()

	// Folders without files are not part of a transfer; create them. The
	// others appear as their files are written.
	if st.IsDir() && len(u.files) == 0 && len(emptyDirs) == 0 {
		emptyDirs = []string{""}
	}
	for _, rel := range emptyDirs {
		if err := c.mkdir(ctx, joinRemote(remote, rel, c.windows)); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}
	if len(u.files) == 0 {
		return nil
	}

	u.j = c.newJob()
	defer c.endJob(u.j)
	err = u.run(ctx)
	if err != nil {
		// Let the peer drop its job and partial file.
		c.cancel(u.j.id)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return err
}

// scan collects the files below dir, and the folders that hold nothing.
func (u *upload) scan(dir string) (emptyDirs []string, err error) {
	sep := remoteSep(u.c.windows)
	wire := func(rel string) (string, error) {
		segs := strings.Split(rel, string(filepath.Separator))
		for _, s := range segs {
			if strings.ContainsAny(s, `/\`) {
				return "", fmt.Errorf("%s: the name cannot be used on the remote side", filepath.Join(dir, rel))
			}
		}
		return strings.Join(segs, sep), nil
	}
	err = filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		hidden := !u.opt.ShowHidden && strings.HasPrefix(e.Name(), ".")
		if e.IsDir() {
			if hidden {
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(dir, path)
			w, err := wire(rel)
			if err != nil {
				return err
			}
			if kids, err := os.ReadDir(path); err == nil && len(kids) == 0 {
				emptyDirs = append(emptyDirs, w)
			}
			return nil
		}
		if hidden {
			return nil
		}
		// Links to files are copied as the files; other links and special
		// files are left out.
		st, err := os.Stat(path)
		if err != nil || !st.Mode().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		w, err := wire(rel)
		if err != nil {
			return err
		}
		u.files = append(u.files, upFile{rel: filepath.ToSlash(rel), wire: w, local: path, size: st.Size(), mtime: st.ModTime().Unix()})
		return nil
	})
	return emptyDirs, err
}

func (u *upload) run(ctx context.Context) error {
	c := u.c
	entries := make([]*pb.FileEntry, len(u.files))
	for i, f := range u.files {
		entries[i] = &pb.FileEntry{EntryType: pb.FileType_File, Name: f.wire, Size: uint64(f.size), ModifiedTime: uint64(max(f.mtime, 0))}
	}
	err := c.action(&pb.FileAction{Union: &pb.FileAction_Receive{Receive: &pb.FileTransferReceiveRequest{
		Id:        u.j.id,
		Path:      u.root,
		Files:     entries,
		TotalSize: uint64(u.total),
	}}})
	if err != nil {
		return err
	}
	u.progress(true)
	// An unknown version gets the digest dialogue too: never overwrite
	// behind the peer's back.
	digests := c.version == 0 || c.version >= digestSince
	for i := range u.files {
		if err := u.pending(ctx); err != nil {
			return err
		}
		f := &u.files[i]
		u.cur, u.sent = f, 0
		var offset int64
		var skip bool
		if digests {
			if skip, offset, err = u.negotiate(ctx, i); err != nil {
				return err
			}
		}
		if skip {
			u.skipped++
			u.total -= f.size
			u.progress(true)
			continue
		}
		if err := u.sendFile(ctx, i, offset); err != nil {
			return err
		}
		u.filesDone++
		u.progress(true)
	}
	u.cur = nil
	return u.finish(ctx)
}

// negotiate offers the file's digest and settles overwrite, skip or resume.
// The peer answers with a send_confirm when it has no such file, or with
// its own copy's digest, which we answer in turn (ui_cm_interface.rs
// CheckDigest).
func (u *upload) negotiate(ctx context.Context, n int) (skip bool, offset int64, err error) {
	c, f := u.c, &u.files[n]
	// The peer honours a resume offset for the job's first file only: its
	// write job compares the confirmation with its current file number,
	// which only moves when data arrives (fs.rs confirm).
	resume := u.opt.Resume && n == 0 && c.version >= resumeSince
	err = c.response(&pb.FileResponse{Union: &pb.FileResponse_Digest{Digest: &pb.FileTransferDigest{
		Id:           u.j.id,
		FileNum:      int32(n),
		LastModified: uint64(max(f.mtime, 0)),
		FileSize:     uint64(f.size),
		IsResume:     resume,
	}}})
	if err != nil {
		return false, 0, err
	}
	for {
		m, err := c.next(ctx, u.j, c.timeout)
		if err != nil {
			return false, 0, fmt.Errorf("upload %s: %w", u.remotePath(f), err)
		}
		switch v := m.(type) {
		case *pb.FileTransferSendConfirmRequest:
			if int(v.GetFileNum()) == n {
				return v.GetSkip(), 0, nil
			}
		case *pb.FileTransferDigest:
			if int(v.GetFileNum()) != n {
				continue
			}
			// The peer has a copy already, or the part of one.
			partial := v.GetTransferredSize()
			switch {
			case resume && v.GetIsIdentical() && partial > 0 && partial <= uint64(f.size) && partial <= math.MaxUint32:
				offset = int64(partial)
			case u.opt.SkipExisting, u.opt.Resume && v.GetIsIdentical() && partial == 0:
				skip = true
			}
			return skip, offset, c.confirm(u.j.id, n, skip, uint32(offset))
		case *pb.FileTransferError:
			return false, 0, u.remoteErr(v)
		case error:
			return false, 0, v
		}
	}
}

func (u *upload) sendFile(ctx context.Context, n int, offset int64) error {
	f := &u.files[n]
	in, err := os.Open(f.local)
	if err != nil {
		return err
	}
	defer in.Close()
	if offset > 0 {
		if _, err := in.Seek(offset, io.SeekStart); err != nil {
			return err
		}
		u.sent, u.done = offset, u.done+offset
	}
	compress := !isCompressedName(f.local)
	buf := make([]byte, blockSize)
	for {
		k, err := io.ReadFull(in, buf)
		if k > 0 {
			if err := u.pending(ctx); err != nil {
				return err
			}
			if err := u.sendBlock(n, buf[:k], compress); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	// An empty block ends the file (and creates it when it is empty).
	return u.sendBlock(n, nil, false)
}

// sendBlock sends data the way fs.rs read does: compressed when that makes
// it smaller. Peers take uncompressed blocks as well.
func (u *upload) sendBlock(n int, data []byte, compress bool) error {
	b := &pb.FileTransferBlock{Id: u.j.id, FileNum: int32(n), Data: data}
	if compress && len(data) > 0 {
		if z := u.c.enc.EncodeAll(data, make([]byte, 0, len(data)/2)); len(z) < len(data) {
			b.Data, b.Compressed = z, true
		}
	}
	if err := u.c.response(&pb.FileResponse{Union: &pb.FileResponse_Block{Block: b}}); err != nil {
		return err
	}
	u.sent += int64(len(data))
	u.done += int64(len(data))
	u.progress(false)
	return nil
}

// finish tells the peer we are done and waits for it to confirm (it
// finalizes the last file then).
func (u *upload) finish(ctx context.Context) error {
	c, n := u.c, len(u.files)
	var err error
	if n == 1 && u.skipped == 1 {
		// A single skipped file is reported as such, so that the peer
		// leaves its copy untouched (rdweb upload.ts).
		err = c.response(&pb.FileResponse{Union: &pb.FileResponse_Error{Error: &pb.FileTransferError{Id: u.j.id, Error: "skipped", FileNum: 1}}})
	} else {
		err = c.response(&pb.FileResponse{Union: &pb.FileResponse_Done{Done: &pb.FileTransferDone{Id: u.j.id, FileNum: int32(n)}}})
	}
	if err != nil {
		return err
	}
	for {
		m, err := c.next(ctx, u.j, c.timeout)
		if errors.Is(err, ErrTimeout) {
			return fmt.Errorf("upload %s: %w", u.root, ErrUnconfirmed)
		}
		if err != nil {
			return err
		}
		switch v := m.(type) {
		case *pb.FileTransferDone:
			u.progress(true)
			return nil
		case *pb.FileTransferError:
			if v.GetError() == "skipped" {
				u.progress(true)
				return nil
			}
			return u.remoteErr(v)
		case error:
			return v
		}
	}
}

// pending fails on cancellation and on an error the peer sent meanwhile.
func (u *upload) pending(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-u.c.dead:
		return u.c.deadErr()
	default:
	}
	for {
		switch v := u.j.poll().(type) {
		case nil:
			return nil
		case *pb.FileTransferError:
			return u.remoteErr(v)
		case error:
			return v
		}
	}
}

func (u *upload) remotePath(f *upFile) string {
	return joinRemote(u.root, f.wire, u.c.windows)
}

func (u *upload) remoteErr(e *pb.FileTransferError) error {
	path := u.root
	if n := int(e.GetFileNum()); n >= 0 && n < len(u.files) {
		path = u.remotePath(&u.files[n])
	}
	return &RemoteError{Op: "upload", Path: path, Msg: e.GetError()}
}

func (u *upload) progress(force bool) {
	p := Progress{Done: u.done, Total: u.total, Files: len(u.files), FilesDone: u.filesDone, FilesSkipped: u.skipped}
	if u.cur != nil {
		p.Name, p.FileDone, p.FileTotal = u.cur.rel, u.sent, max(u.cur.size, u.sent)
	}
	u.meter.report(force, p)
}

// isCompressedName mirrors fs.rs is_compressed_file: not worth compressing.
func isCompressedName(name string) bool {
	switch strings.ToLower(strings.TrimPrefix(filepath.Ext(name), ".")) {
	case "xz", "gz", "zip", "7z", "rar", "bz2", "tgz", "png", "jpg":
		return true
	}
	return false
}
