package files

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bropines/rdcli/internal/pb"
)

const localOS = runtime.GOOS

// partSuffix marks a file that is still arriving; it is renamed over the
// destination once complete, so an interrupted download never leaves a
// truncated file under the real name.
const partSuffix = ".rdpart"

type dlFile struct {
	rel   string // "/"-separated, below the transfer's root
	local string
	size  int64
	mtime int64 // seconds since the epoch, 0 if unknown
}

type download struct {
	c      *Client
	j      *job
	opt    TransferOptions
	remote string
	files  []dlFile

	cur      *dlFile
	curNum   int
	out      *os.File
	received int64
	seen     int // highest file number announced so far

	done, total        int64
	filesDone, skipped int
	meter              progressMeter
}

// Download copies a remote file, or with Recursive a folder, to localPath.
// As with cp, an existing local folder (or a localPath ending in a
// separator) receives the item under its remote name; otherwise localPath
// is the name of the copy. remotePath may start with "~".
func (c *Client) Download(ctx context.Context, remotePath, localPath string, opt TransferOptions) error {
	remote, err := c.resolve(ctx, remotePath)
	if err != nil {
		return err
	}
	if err := c.check(); err != nil {
		return err
	}
	if err := c.acquire(ctx, c.transferSem); err != nil {
		return err
	}
	defer func() { <-c.transferSem }()

	j := c.newJob()
	defer c.endJob(j)
	d := &download{c: c, j: j, opt: opt, remote: remote, seen: -1, meter: progressMeter{fn: opt.Progress}}
	finished, err := d.run(ctx, localPath)
	if err != nil {
		d.abort()
	}
	if !finished {
		c.cancel(j.id)
	}
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// run reports whether the peer's job is over, and the outcome.
func (d *download) run(ctx context.Context, localPath string) (finished bool, err error) {
	c := d.c
	err = c.action(&pb.FileAction{Union: &pb.FileAction_Send{Send: &pb.FileTransferSendRequest{
		Id:            d.j.id,
		Path:          d.remote,
		IncludeHidden: d.opt.ShowHidden,
	}}})
	if err != nil {
		return true, err
	}
	// The peer answers with the job's file list, or an error.
	var fd *pb.FileDirectory
	for fd == nil {
		m, err := c.next(ctx, d.j, c.timeout)
		if err != nil {
			return false, fmt.Errorf("download %s: %w", d.remote, err)
		}
		switch v := m.(type) {
		case *pb.FileDirectory:
			fd = v
		case *pb.FileTransferError:
			return true, d.remoteErr(v)
		case error:
			return false, v
		default:
			return false, d.protocolErr("file data before the file list")
		}
	}
	// A file is announced as one entry without a name (fs.rs
	// read_dir_recursive); anything else is a folder's files, with their
	// paths below it. Empty folders are not part of the list.
	entries := fd.GetEntries()
	single := len(entries) == 1 && entries[0].GetName() == ""
	if !single && !d.opt.Recursive {
		return false, fmt.Errorf("%s: %w", d.remote, ErrIsDirectory)
	}
	dest := localPath
	if dest == "" {
		dest = "."
	}
	if st, err := os.Stat(dest); os.IsPathSeparator(dest[len(dest)-1]) || err == nil && st.IsDir() {
		dest = filepath.Join(dest, localName(baseRemote(d.remote, c.windows)))
	}
	for _, e := range entries {
		f := dlFile{size: int64(e.GetSize()), mtime: int64(e.GetModifiedTime())}
		if single {
			f.rel, f.local = filepath.Base(dest), dest
		} else {
			segs, err := safeSegments(e.GetName())
			if err == nil {
				var rel string
				if rel, err = localRel(segs, c.goos); err == nil {
					f.rel, f.local = strings.Join(segs, "/"), filepath.Join(dest, rel)
				}
			}
			if err != nil {
				return false, fmt.Errorf("download %s: the remote device sent an unsafe file name: %w", d.remote, err)
			}
		}
		d.total += f.size
		d.files = append(d.files, f)
	}
	if !single {
		if err := os.MkdirAll(dest, 0o777); err != nil {
			return false, err
		}
	}
	d.progress(true)
	if len(entries) == 0 {
		// Nothing to wait for: not every peer ends a job without files.
		c.cancel(d.j.id)
		d.emptyDirs(ctx, dest)
		return true, nil
	}

	for {
		m, err := c.next(ctx, d.j, c.idle)
		if err != nil {
			return false, fmt.Errorf("download %s: %w", d.remote, err)
		}
		switch v := m.(type) {
		case *pb.FileTransferDigest:
			err = d.onDigest(v)
		case *pb.FileTransferBlock:
			err = d.onBlock(v)
		case *pb.FileTransferDone:
			if err := d.finishFile(); err != nil {
				return true, err
			}
			if !single {
				d.emptyDirs(ctx, dest)
			}
			d.progress(true)
			return true, nil
		case *pb.FileTransferError:
			// A job whose only file we skipped ends with "skipped"
			// (fs.rs job_error).
			if v.GetError() == "skipped" && d.skipped > 0 {
				d.progress(true)
				return true, nil
			}
			return true, d.remoteErr(v)
		case error:
			err = v
		}
		if err != nil {
			return false, err
		}
	}
}

// onDigest handles the announcement of the next file. Peers that know the
// overwrite dialogue (1.1.10+, and only for clients that do too) send a
// digest and wait for our send_confirm before the file's data.
func (d *download) onDigest(v *pb.FileTransferDigest) error {
	n := int(v.GetFileNum())
	if n < 0 || n >= len(d.files) {
		return d.protocolErr(fmt.Sprintf("file number %d is not in the file list", n))
	}
	if d.cur != nil && d.curNum == n {
		return nil // repeated digest
	}
	if n <= d.seen {
		return d.protocolErr(fmt.Sprintf("file %d announced again", n))
	}
	if err := d.finishFile(); err != nil {
		return err
	}
	d.seen = n
	f := &d.files[n]
	size := int64(v.GetFileSize())
	d.total += size - f.size
	f.size = size
	if lm := int64(v.GetLastModified()); lm != 0 {
		f.mtime = lm
	}
	if st, err := os.Stat(f.local); err == nil && st.Mode().IsRegular() {
		same := st.Size() == size && f.mtime != 0 && st.ModTime().Unix() == f.mtime
		if d.opt.SkipExisting || d.opt.Resume && same {
			d.skipped++
			d.total -= size
			d.progress(true)
			return d.c.confirm(d.j.id, n, true, 0)
		}
	}
	// offset_blk is, despite its name, a 32-bit byte offset the sender
	// seeks to (fs.rs set_stream_offset).
	var offset int64
	if d.opt.Resume {
		if st, err := os.Stat(f.local + partSuffix); err == nil && st.Mode().IsRegular() &&
			st.Size() > 0 && st.Size() < size && st.Size() <= math.MaxUint32 {
			offset = st.Size()
		}
	}
	if err := d.open(n, offset); err != nil {
		return err
	}
	return d.c.confirm(d.j.id, n, false, uint32(offset))
}

func (d *download) onBlock(v *pb.FileTransferBlock) error {
	n := int(v.GetFileNum())
	if n < 0 || n >= len(d.files) {
		return d.protocolErr(fmt.Sprintf("file number %d is not in the file list", n))
	}
	if d.cur == nil || d.curNum != n {
		if n <= d.seen {
			return d.protocolErr(fmt.Sprintf("data for file %d, which is not the current one", n))
		}
		// Peers without the digest dialogue just start sending.
		if err := d.finishFile(); err != nil {
			return err
		}
		d.seen = n
		if err := d.open(n, 0); err != nil {
			return err
		}
	}
	data := v.GetData()
	if len(data) == 0 {
		// An empty block ends the file (fs.rs read at end of file).
		return d.finishFile()
	}
	if len(data) > maxBlockSize {
		return d.protocolErr(fmt.Sprintf("a %d byte block (limit %d)", len(data), maxBlockSize))
	}
	if v.GetCompressed() {
		var err error
		if data, err = d.c.inflate(data); err != nil {
			return fmt.Errorf("download %s: %w", d.remote, err)
		}
	}
	if _, err := d.out.Write(data); err != nil {
		return err
	}
	d.received += int64(len(data))
	d.done += int64(len(data))
	d.progress(false)
	return nil
}

func (d *download) open(n int, offset int64) error {
	f := &d.files[n]
	if err := os.MkdirAll(filepath.Dir(f.local), 0o777); err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if offset > 0 {
		flags = os.O_WRONLY | os.O_APPEND
	}
	out, err := os.OpenFile(f.local+partSuffix, flags, 0o666)
	if err != nil {
		return err
	}
	d.cur, d.curNum, d.out, d.received = f, n, out, offset
	d.done += offset
	d.progress(true)
	return nil
}

// finishFile completes the file that is arriving, if there is one.
func (d *download) finishFile() error {
	f := d.cur
	if f == nil {
		return nil
	}
	err := d.out.Close()
	d.out = nil
	if err != nil {
		return err
	}
	if err := os.Rename(f.local+partSuffix, f.local); err != nil {
		return err
	}
	d.cur = nil
	if f.mtime > 0 {
		os.Chtimes(f.local, time.Time{}, time.Unix(f.mtime, 0))
	}
	d.filesDone++
	d.progress(true)
	return nil
}

// abort drops the file that was arriving; Resume keeps its part for the
// next attempt.
func (d *download) abort() {
	if d.out != nil {
		d.out.Close()
		d.out = nil
	}
	if d.cur != nil && !d.opt.Resume {
		os.Remove(d.cur.local + partSuffix)
	}
}

// emptyDirs recreates the folder's empty sub-folders.
func (d *download) emptyDirs(ctx context.Context, dest string) {
	for _, p := range d.c.readEmptyDirs(ctx, d.remote, d.opt.ShowHidden) {
		rel, ok := relRemote(d.remote, p, d.c.windows)
		if !ok || rel == "" {
			continue
		}
		segs, err := safeSegments(rel)
		if err != nil {
			continue
		}
		if local, err := localRel(segs, d.c.goos); err == nil {
			os.MkdirAll(filepath.Join(dest, local), 0o777)
		}
	}
}

func (d *download) progress(force bool) {
	p := Progress{Done: d.done, Total: d.total, Files: len(d.files), FilesDone: d.filesDone, FilesSkipped: d.skipped}
	if d.cur != nil {
		p.Name, p.FileDone, p.FileTotal = d.cur.rel, d.received, max(d.cur.size, d.received)
	}
	d.meter.report(force, p)
}

func (d *download) remoteErr(e *pb.FileTransferError) error {
	// Peers move past a file before reporting that it could not be read.
	path := d.remote
	if d.cur != nil && len(d.files) > 1 {
		path = joinRemote(d.remote, d.cur.rel, d.c.windows)
	}
	return &RemoteError{Op: "download", Path: path, Msg: e.GetError()}
}

func (d *download) protocolErr(what string) error {
	return fmt.Errorf("download %s: protocol error: %s", d.remote, what)
}
