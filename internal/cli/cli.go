// Package cli implements the rdcli commands.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/bropines/rdcli/internal/peer"
	"github.com/bropines/rdcli/internal/rendezvous"
	"github.com/bropines/rdcli/internal/term"
)

// Version is set at build time (-ldflags "-X github.com/bropines/rdcli/internal/cli.Version=...").
var Version = "dev"

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string) error
}

var commands []command

func register(name, summary string, run func(context.Context, []string) error) {
	commands = append(commands, command{name, summary, run})
}

// exitError carries a process exit code.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

// usageError is a bad command line.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// Main runs rdcli and returns the process exit code.
func Main(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		if len(args) > 1 {
			return Main([]string{args[1], "--help"})
		}
		printUsage(os.Stdout)
		return 0
	}
	if args[0] == "--version" || args[0] == "-V" {
		args[0] = "version"
	}
	for _, c := range commands {
		if c.name != args[0] {
			continue
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			// A blocked prompt cannot see ctx: give the terminal back and go.
			if term.InterruptPrompt() {
				os.Exit(130)
			}
			// The first signal stops gracefully; a second one kills.
			stop()
		}()
		err := c.run(ctx, args[1:])
		return report(err)
	}
	fmt.Fprintf(os.Stderr, "rdcli: unknown command %q\n\n", args[0])
	printUsage(os.Stderr)
	return 2
}

func report(err error) int {
	if err == nil {
		return 0
	}
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	var ue usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(os.Stderr, "rdcli: %s\n", ue.msg)
		return 2
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	fmt.Fprintf(os.Stderr, "rdcli: %s\n", term.Sanitize(humanize(err)))
	return 1
}

// humanize adds a hint to the errors people hit most.
func humanize(err error) string {
	msg := err.Error()
	var re *rendezvous.Error
	if errors.As(err, &re) {
		switch re.Code {
		case rendezvous.CodeLoginRequired:
			return msg + " (the server requires a signed-in client: run rdcli login)"
		case rendezvous.CodeKeyMismatch:
			return msg + " (check --key / the server profile)"
		case rendezvous.CodeOffline:
			return msg
		}
	}
	var pe *peer.Error
	if errors.As(err, &pe) {
		switch pe.Code {
		case peer.CodePermissionDenied:
			return msg + " (enable it in the device's RustDesk settings, Security > Permissions)"
		case peer.CodeApprovalUnavailable:
			return msg + " (connect with a password instead of --approval)"
		}
	}
	return msg
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "rdcli %s: a console RustDesk client\n\nUsage:\n  rdcli <command> [flags] [args]\n\nCommands:\n", Version)
	sorted := append([]command(nil), commands...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })
	for _, c := range sorted {
		fmt.Fprintf(w, "  %-9s %s\n", c.name, c.summary)
	}
	io.WriteString(w, `
Run "rdcli <command> --help" for the flags of a command.

Examples:
  rdcli server import                     use the servers of the installed RustDesk client
  rdcli login                             sign in to the API server (MUST_LOGIN servers, address book)
  rdcli shell 123456789                   remote shell (~. disconnects)
  rdcli forward 123456789 -L 2222:22      local port 2222 -> port 22 on the device
  ssh -o ProxyCommand="rdcli pipe 123456789 %h:%p" user@localhost
  rdcli cp report.pdf 123456789:Desktop/  copy files (rdcli cp -r for directories)
`)
}

// parseFlags parses flags anywhere among the arguments (Go's flag package
// stops at the first positional one). Everything after "--" is positional.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var rest []string
	for i, a := range args {
		if a == "--" {
			rest = args[i+1:]
			args = args[:i]
			break
		}
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return append(pos, rest...), nil
}

func newFlagSet(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: rdcli %s %s\n\nFlags:\n", name, usage)
		fs.PrintDefaults()
	}
	return fs
}

func platformName() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "darwin":
		return "Mac OS"
	case "android":
		return "Android"
	default:
		return "Linux"
	}
}

func hostname() string {
	h, _ := os.Hostname()
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return h
}
