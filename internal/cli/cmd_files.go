package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bropines/rdcli/internal/files"
	"github.com/bropines/rdcli/internal/pb"
	"github.com/bropines/rdcli/internal/term"
)

func init() {
	register("ls", "list a directory on a device", runLs)
	register("cp", "copy files to or from a device", runCp)
}

// openFiles logs in for a file-transfer session.
func openFiles(ctx context.Context, t *target, showHidden bool) (*files.Client, func(), error) {
	s, err := t.connect(ctx, pb.ConnType_FILE_TRANSFER, files.LoginFields("", showHidden), files.LoginErrorCode)
	if err != nil {
		return nil, nil, err
	}
	if pi := s.PeerInfo; pi != nil && pi.GetUsername() == "" && len(pi.GetWindowsSessions().GetSessions()) == 0 {
		s.Close("")
		return nil, nil, errors.New("no user is logged on at the remote device; log on there first")
	}
	kctx, cancel := context.WithCancel(ctx)
	go s.KeepAlive(kctx, 20*time.Second)
	c := files.New(s, t.flags.debugf)
	return c, func() { cancel(); c.Close() }, nil
}

func runLs(ctx context.Context, args []string) error {
	fs := newFlagSet("ls", "<device>[:path] [flags]")
	var cf connFlags
	cf.register(fs, true)
	all := fs.Bool("a", false, "include hidden files")
	long := fs.Bool("l", false, "long listing: size and modification time")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return usagef("ls takes one device[:path]")
	}
	peerArg, path, _ := strings.Cut(pos[0], ":")
	t, err := cf.resolve(peerArg)
	if err != nil {
		return err
	}
	if err := t.secrets(ctx); err != nil {
		return err
	}
	c, done, err := openFiles(ctx, t, *all)
	if err != nil {
		return err
	}
	defer done()
	entries, err := c.List(ctx, path, *all)
	if err != nil {
		return err
	}
	// The device lists in directory order; sort by name like ls.
	sort.SliceStable(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for _, e := range entries {
		name := e.Name
		if e.IsDir || e.IsDrive {
			name += "/"
		}
		if !*long {
			fmt.Fprintln(w, name)
			continue
		}
		kind := "-"
		switch {
		case e.IsDrive:
			kind = "drive"
		case e.IsDir:
			kind = "dir"
		case e.IsSymlink:
			kind = "link"
		}
		mod := ""
		if !e.ModTime.IsZero() {
			mod = e.ModTime.Local().Format("2006-01-02 15:04")
		}
		size := ""
		if !e.IsDir && !e.IsDrive {
			size = humanBytes(e.Size)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", kind, size, mod, name)
	}
	return w.Flush()
}

func runCp(ctx context.Context, args []string) error {
	fs := newFlagSet("cp", "[-r] <source>... <destination>   (one side is <device>:<path>)")
	var cf connFlags
	cf.register(fs, true)
	recursive := fs.Bool("r", false, "copy directories recursively")
	resume := fs.Bool("resume", false, "continue partial files instead of starting over")
	skip := fs.Bool("skip-existing", false, "skip files that already exist with the same size and time")
	noHidden := fs.Bool("no-hidden", false, "leave out hidden files (dot files) when copying directories")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 2 {
		fs.Usage()
		return usagef("cp takes a source and a destination")
	}
	srcs, dst := pos[:len(pos)-1], pos[len(pos)-1]
	dstPeer, dstPath, dstRemote := splitPeerPath(dst)
	var peerArg string
	remotes := 0
	for _, s := range srcs {
		p, _, remote := splitPeerPath(s)
		if remote {
			remotes++
			if peerArg != "" && p != peerArg {
				return usagef("all remote sources must be on one device")
			}
			peerArg = p
		}
	}
	switch {
	case dstRemote && remotes > 0:
		return usagef("copying between two remote paths is not supported")
	case !dstRemote && remotes == 0:
		return usagef("one side must be <device>:<path> (use cp for local copies)")
	case !dstRemote && remotes != len(srcs):
		return usagef("mixing local and remote sources is not supported")
	case dstRemote:
		peerArg = dstPeer
	}
	t, err := cf.resolve(peerArg)
	if err != nil {
		return err
	}
	if err := t.secrets(ctx); err != nil {
		return err
	}
	c, done, err := openFiles(ctx, t, !*noHidden)
	if err != nil {
		return err
	}
	defer done()

	bar := newProgressBar(!cf.quiet && term.IsTerminal(os.Stderr))
	opt := files.TransferOptions{
		Recursive: *recursive, ShowHidden: !*noHidden, SkipExisting: *skip, Resume: *resume,
		Progress: bar.update,
	}
	if len(srcs) > 1 && !strings.HasSuffix(dstPath, "/") && !strings.HasSuffix(dstPath, `\`) && dstPath != "" && dstPath != "~" {
		if dstRemote {
			dstPath += map[bool]string{true: `\`, false: "/"}[c.Windows()]
		} else if st, err := os.Stat(dstPath); err != nil || !st.IsDir() {
			return usagef("with several sources the destination must be a directory")
		}
	}
	for _, src := range srcs {
		var err error
		if dstRemote {
			err = c.Upload(ctx, src, dstPath, opt)
		} else {
			_, rpath, _ := splitPeerPath(src)
			err = c.Download(ctx, rpath, dstPath, opt)
		}
		bar.finish()
		if err != nil {
			if errors.Is(err, files.ErrIsDirectory) {
				return usagef("%v (use -r)", err)
			}
			return err
		}
	}
	return nil
}

// progressBar draws one status line on stderr.
type progressBar struct {
	on    bool
	start time.Time
	last  time.Time
	drawn bool
}

func newProgressBar(on bool) *progressBar { return &progressBar{on: on, start: time.Now()} }

func (b *progressBar) update(p files.Progress) {
	if !b.on {
		return
	}
	now := time.Now()
	if now.Sub(b.last) < 150*time.Millisecond && p.Done < p.Total {
		return
	}
	b.last = now
	rate := ""
	if secs := now.Sub(b.start).Seconds(); secs > 0.5 {
		rate = " " + humanBytes(int64(float64(p.Done)/secs)) + "/s"
	}
	pct := 100.0
	if p.Total > 0 {
		pct = float64(p.Done) * 100 / float64(p.Total)
	}
	name := p.Name
	if len(name) > 40 {
		name = "..." + name[len(name)-37:]
	}
	fmt.Fprintf(os.Stderr, "\r\033[K%5.1f%% %s/%s%s  [%d/%d] %s", pct, humanBytes(p.Done), humanBytes(p.Total), rate, p.FilesDone, p.Files, name)
	b.drawn = true
}

func (b *progressBar) finish() {
	if b.drawn {
		fmt.Fprint(os.Stderr, "\n")
		b.drawn = false
	}
	b.start = time.Now()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
