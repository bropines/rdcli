package cli

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/bropines/rdcli/internal/forward"
	"github.com/bropines/rdcli/internal/pb"
	"github.com/bropines/rdcli/internal/peer"
	"github.com/bropines/rdcli/internal/term"
)

func init() {
	register("shell", "open a remote shell on a device", runShell)
	register("forward", "forward local ports to addresses reachable from a device", runForward)
	register("pipe", "connect stdin/stdout to an address reachable from a device (ssh ProxyCommand)", runPipe)
}

func runShell(ctx context.Context, args []string) error {
	fs := newFlagSet("shell", "<device> [flags]")
	var cf connFlags
	cf.register(fs, false)
	persistent := fs.Bool("persistent", false, "keep the shell running on the device after disconnecting (reattach with --service)")
	service := fs.String("service", "", "reattach to a persistent shell by its service id")
	command := fs.String("c", "", "type this command into the shell, then exit (output includes the shell's echo)")
	osUser := fs.String("os-user", "", "Windows: run the shell as this administrator account of the device (asks for its password)")
	escape := fs.String("e", "~", `escape character at the start of a line ("none" disables)`)
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return usagef("shell takes one device")
	}
	t, err := cf.resolve(pos[0])
	if err != nil {
		return err
	}
	if err := t.secrets(ctx); err != nil {
		return err
	}
	opts := term.ShellOptions{Persistent: *persistent, ServiceID: *service, Command: *command}
	switch {
	case *escape == "none":
		opts.Escape = -1
	case len(*escape) == 1:
		opts.Escape = int((*escape)[0])
	default:
		return usagef("-e takes one character or none")
	}
	var osPass string
	if *osUser != "" {
		if osPass, err = term.ReadSecretTTY(fmt.Sprintf("Password of %s on the device: ", *osUser)); err != nil {
			return err
		}
	}
	s, err := t.connect(ctx, pb.ConnType_TERMINAL, term.LoginFields(opts, *osUser, osPass), term.LoginErrorCode)
	if err != nil {
		return err
	}
	defer s.Close("")
	res, err := term.RunShell(ctx, s, opts)
	if err != nil {
		return err
	}
	if res.Detached && res.ServiceID != "" {
		fmt.Fprintf(os.Stderr, "rdcli: the shell keeps running; reattach with: rdcli shell %s --service %s\n", t.peerID, res.ServiceID)
		return nil
	}
	if res.ExitCode != 0 {
		return exitError{res.ExitCode}
	}
	return nil
}

// dialer returns a forward.Dialer that logs in to the target, reusing the
// password that worked for later logins.
func (t *target) dialer() forward.Dialer {
	var mu sync.Mutex
	return func(ctx context.Context, tg forward.Target, mux bool) (*peer.Session, error) {
		mu.Lock()
		defer mu.Unlock()
		return t.connect(ctx, pb.ConnType_PORT_FORWARD, forward.LoginFields(tg, mux), forward.LoginErrorCode)
	}
}

func modeFrom(legacy, mux bool) (forward.Mode, error) {
	switch {
	case legacy && mux:
		return 0, usagef("--legacy and --mux exclude each other")
	case legacy:
		return forward.ModeLegacy, nil
	case mux:
		return forward.ModeMux, nil
	}
	return forward.ModeAuto, nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprint(*m) }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func runForward(ctx context.Context, args []string) error {
	fs := newFlagSet("forward", "<device> -L [bind:]port:host:hostport [-L ...] [flags]")
	var cf connFlags
	cf.register(fs, true)
	var specs multiFlag
	fs.Var(&specs, "L", "forward [bind_address:]port:host:hostport (host as seen from the device; repeatable)")
	legacy := fs.Bool("legacy", false, "force the legacy mode (one login per connection, NOT encrypted after login)")
	mux := fs.Bool("mux", false, "require the multiplexed mode (RustDesk 1.5+), fail otherwise")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || len(specs) == 0 {
		fs.Usage()
		return usagef("forward takes one device and at least one -L")
	}
	mode, err := modeFrom(*legacy, *mux)
	if err != nil {
		return err
	}
	var parsed []forward.Spec
	for _, s := range specs {
		sp, err := forward.ParseSpec(s)
		if err != nil {
			return usagef("%v", err)
		}
		parsed = append(parsed, sp)
	}
	t, err := cf.resolve(pos[0])
	if err != nil {
		return err
	}
	if err := t.secrets(ctx); err != nil {
		return err
	}
	dial := t.dialer()
	errc := make(chan error, len(parsed))
	for _, sp := range parsed {
		m := &forward.Mapping{
			Target: sp.Target, Dial: dial, Mode: mode, Logf: cf.logf,
			OnLegacy: func() {
				cf.logf("warning: the device has no multiplexed forwarding; this mapping is NOT encrypted between you and the device")
			},
		}
		go func(bind string) { errc <- m.Listen(ctx, bind) }(sp.Bind)
	}
	cf.logf("press Ctrl+C to stop")
	for range parsed {
		if err := <-errc; err != nil {
			return err
		}
	}
	return nil
}

func runPipe(ctx context.Context, args []string) error {
	fs := newFlagSet("pipe", "<device> <host:port> [flags]")
	var cf connFlags
	cf.register(fs, false)
	legacy := fs.Bool("legacy", false, "force the legacy mode (NOT encrypted after login)")
	mux := fs.Bool("mux", false, "require the multiplexed mode (RustDesk 1.5+)")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		fs.Usage()
		return usagef("pipe takes a device and host:port")
	}
	mode, err := modeFrom(*legacy, *mux)
	if err != nil {
		return err
	}
	tg, err := forward.ParseTarget(pos[1])
	if err != nil {
		return usagef("%v", err)
	}
	t, err := cf.resolve(pos[0])
	if err != nil {
		return err
	}
	if err := t.secrets(ctx); err != nil {
		return err
	}
	m := &forward.Mapping{
		Target: tg, Dial: t.dialer(), Mode: mode, Logf: cf.debugf,
		OnLegacy: func() {
			cf.logf("warning: the device has no multiplexed forwarding; this pipe is NOT encrypted between you and the device")
		},
	}
	defer m.Close()
	return m.Serve(ctx, forward.Stdio{In: os.Stdin, Out: os.Stdout})
}
