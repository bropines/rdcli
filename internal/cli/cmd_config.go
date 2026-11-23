package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/bropines/rdcli/internal/api"
	"github.com/bropines/rdcli/internal/config"
	"github.com/bropines/rdcli/internal/crypto"
	"github.com/bropines/rdcli/internal/term"
)

func init() {
	register("server", "manage server profiles (add, import, list, default, remove)", runServer)
	register("login", "sign in to the API server (RD Panel)", runLogin)
	register("logout", "sign out of the API server", runLogout)
	register("peers", "list the devices in your address books", runPeers)
	register("forget", "forget a remembered device password", runForget)
	register("version", "print the version", func(context.Context, []string) error {
		fmt.Println("rdcli", Version)
		return nil
	})
}

func runServer(ctx context.Context, args []string) error {
	sub := "list"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	switch sub {
	case "list", "ls":
		if len(cfg.Servers) == 0 {
			fmt.Println("no server profiles; add one with rdcli server import or rdcli server add")
			return nil
		}
		def, _, _ := cfg.Server("")
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "\tNAME\tID SERVER\tRELAY\tAPI\tSIGNED IN")
		for _, n := range cfg.ServerNames() {
			s := cfg.Servers[n]
			mark := ""
			if n == def {
				mark = "*"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", mark, n, s.IDServer, dash(s.Relay), dash(s.API), dash(s.User))
		}
		return w.Flush()
	case "add", "set":
		fs := newFlagSet("server add", "<name> --id-server host --key KEY [--relay host] [--api URL]")
		var s config.Server
		fs.StringVar(&s.IDServer, "id-server", "", "ID server: host[:port] or ws(s)://host/ws/id")
		fs.StringVar(&s.Relay, "relay", "", "relay server (default: the one the ID server announces)")
		fs.StringVar(&s.Key, "key", "", "server public key (base64, id_ed25519.pub)")
		fs.StringVar(&s.API, "api", "", "API server URL (RD Panel), for rdcli login and the address book")
		fs.BoolVar(&s.Insecure, "insecure", false, "do not verify TLS certificates of wss:// servers")
		makeDefault := fs.Bool("default", false, "make it the default profile")
		pos, err := parseFlags(fs, args)
		if err != nil {
			return err
		}
		if len(pos) != 1 || s.IDServer == "" || s.Key == "" {
			fs.Usage()
			return usagef("server add needs a name, --id-server and --key")
		}
		if _, err := crypto.ParseServerKey(s.Key); err != nil {
			return usagef("%v", err)
		}
		if old := cfg.Servers[pos[0]]; old != nil {
			s.Token, s.User, s.MyID, s.UUID = old.Token, old.User, old.MyID, old.UUID
		}
		cfg.Servers[pos[0]] = &s
		if *makeDefault || len(cfg.Servers) == 1 {
			cfg.DefaultServer = pos[0]
		}
		return saved(cfg, "server profile %q saved", pos[0])
	case "import":
		fs := newFlagSet("server import", "[name] [--from RustDesk2.toml | --config STRING]")
		from := fs.String("from", "", "path of RustDesk2.toml (default: the installed client's)")
		cfgString := fs.String("config", "", `a RustDesk config string (Settings > Network > ID/Relay server > export; "-" reads it from stdin)`)
		pos, err := parseFlags(fs, args)
		if err != nil {
			return err
		}
		name := "default"
		if len(pos) > 0 {
			name = pos[0]
		}
		var s *config.Server
		if *cfgString != "" {
			str := *cfgString
			if str == "-" {
				if str, err = term.ReadPasswordStdin(); err != nil {
					return err
				}
			}
			if s, err = config.ParseConfigString(str); err != nil {
				return usagef("%v", err)
			}
		} else {
			opts, err := config.RustDeskOptions(*from)
			if err != nil {
				return fmt.Errorf("cannot read the RustDesk client's settings: %w", err)
			}
			s = &config.Server{
				IDServer: opts["custom-rendezvous-server"],
				Relay:    opts["relay-server"],
				Key:      opts["key"],
				API:      opts["api-server"],
			}
			if s.IDServer == "" || s.Key == "" {
				return errors.New("the RustDesk client has no custom ID server and key configured")
			}
		}
		if old := cfg.Servers[name]; old != nil {
			s.Token, s.User, s.MyID, s.UUID = old.Token, old.User, old.MyID, old.UUID
		}
		cfg.Servers[name] = s
		if cfg.DefaultServer == "" {
			cfg.DefaultServer = name
		}
		return saved(cfg, "imported %s (relay %s, API %s) as %q", s.IDServer, dash(s.Relay), dash(s.API), name)
	case "default":
		if len(args) != 1 {
			return usagef("server default <name>")
		}
		if cfg.Servers[args[0]] == nil {
			return fmt.Errorf("no server profile %q", args[0])
		}
		cfg.DefaultServer = args[0]
		return saved(cfg, "default server profile: %s", args[0])
	case "remove", "rm":
		if len(args) != 1 {
			return usagef("server remove <name>")
		}
		if cfg.Servers[args[0]] == nil {
			return fmt.Errorf("no server profile %q", args[0])
		}
		delete(cfg.Servers, args[0])
		if cfg.DefaultServer == args[0] {
			cfg.DefaultServer = ""
		}
		return saved(cfg, "server profile %q removed", args[0])
	default:
		return usagef("unknown server command %q (add, import, list, default, remove)", sub)
	}
}

func saved(cfg *config.Config, format string, a ...any) error {
	if err := cfg.Save(); err != nil {
		return err
	}
	fmt.Printf(format+"\n", a...)
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func profileFor(cfg *config.Config, name string) (string, *config.Server, error) {
	n, s, err := cfg.Server(name)
	if err != nil {
		return "", nil, err
	}
	if s == nil {
		return "", nil, usagef("no server profile: run rdcli server import or rdcli server add first")
	}
	return n, s, nil
}

func runLogin(ctx context.Context, args []string) error {
	fs := newFlagSet("login", "[user] [--server name]")
	server := fs.String("server", "", "server profile")
	apiURL := fs.String("api", "", "API server URL (saved in the profile)")
	passwordStdin := fs.Bool("password-stdin", false, "read the password from the first line of stdin")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	name, prof, err := profileFor(cfg, *server)
	if err != nil {
		return err
	}
	if *apiURL != "" {
		prof.API = strings.TrimRight(*apiURL, "/")
	}
	if prof.API == "" {
		return usagef("the profile %q has no API server: pass --api https://panel.example.com", name)
	}
	if prof.UUID == "" {
		var b [16]byte
		rand.Read(b[:])
		prof.UUID = hex.EncodeToString(b[:])
	}
	user := ""
	if len(pos) > 0 {
		user = pos[0]
	} else if user, err = term.ReadLineTTY("Username: "); err != nil {
		return err
	}
	var password string
	if *passwordStdin {
		password, err = term.ReadPasswordStdin()
	} else {
		password, err = term.ReadSecretTTY("Password: ")
	}
	if err != nil {
		return err
	}
	c := &api.Client{Base: prof.API, ID: prof.MyID, UUID: prof.UUID}
	u, err := c.Login(ctx, api.LoginOptions{
		Username: user, Password: password, OS: platformName(), DeviceName: "rdcli (" + hostname() + ")",
		Code: func(kind string, wrong bool) (string, error) {
			label := "Authenticator code: "
			if kind == "email" {
				label = "Code from the e-mail: "
			}
			if wrong {
				label = "Wrong code. " + label
			}
			return term.ReadLineTTY(label)
		},
	})
	if err != nil {
		return err
	}
	prof.Token = c.Token
	prof.User = user
	if u != nil && u.Name != "" {
		prof.User = u.Name
	}
	return saved(cfg, "signed in to %s as %s", prof.API, prof.User)
}

func runLogout(ctx context.Context, args []string) error {
	fs := newFlagSet("logout", "[--server name]")
	server := fs.String("server", "", "server profile")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	_, prof, err := profileFor(cfg, *server)
	if err != nil {
		return err
	}
	if prof.Token == "" {
		fmt.Println("not signed in")
		return nil
	}
	c := &api.Client{Base: prof.API, Token: prof.Token, ID: prof.MyID, UUID: prof.UUID}
	if err := c.Logout(ctx); err != nil && !errors.Is(err, api.ErrUnauthorized) {
		fmt.Fprintf(os.Stderr, "rdcli: the server did not confirm the logout: %v\n", err)
	}
	prof.Token, prof.User = "", ""
	return saved(cfg, "signed out")
}

func runPeers(ctx context.Context, args []string) error {
	fs := newFlagSet("peers", "[filter] [--server name]")
	server := fs.String("server", "", "server profile")
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	_, prof, err := profileFor(cfg, *server)
	if err != nil {
		return err
	}
	if prof.Token == "" || prof.API == "" {
		return errors.New("not signed in: run rdcli login")
	}
	c := &api.Client{Base: prof.API, Token: prof.Token, ID: prof.MyID, UUID: prof.UUID}
	peers, err := c.AllPeers(ctx)
	if err != nil && len(peers) == 0 {
		return err
	}
	filter := ""
	if len(pos) > 0 {
		filter = strings.ToLower(strings.Join(pos, " "))
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tALIAS\tHOSTNAME\tPLATFORM\tTAGS\tBOOK")
	seen := map[string]bool{}
	for _, p := range peers {
		key := p.ID + "\x00" + p.Book
		if seen[key] {
			continue
		}
		seen[key] = true
		line := strings.Join([]string{p.ID, dash(p.Alias), dash(p.Hostname), dash(p.Platform), dash(strings.Join(p.Tags, ",")), p.Book}, "\t")
		if filter != "" && !strings.Contains(strings.ToLower(line), filter) {
			continue
		}
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func runForget(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return usagef("forget <device>")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	id, _ := cfg.ResolvePeer(args[0])
	if !cfg.Forget(id) {
		fmt.Printf("no remembered password for %s\n", id)
		return nil
	}
	return saved(cfg, "forgot the password for %s", id)
}
