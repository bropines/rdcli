package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bropines/rdcli/internal/api"
	"github.com/bropines/rdcli/internal/config"
	"github.com/bropines/rdcli/internal/pb"
	"github.com/bropines/rdcli/internal/peer"
	"github.com/bropines/rdcli/internal/rendezvous"
	"github.com/bropines/rdcli/internal/term"
)

// connFlags are the flags every connecting command takes.
type connFlags struct {
	server        string
	idServer      string
	relay         string
	key           string
	token         string
	insecure      bool
	passwordStdin bool
	approval      bool
	remember      bool
	noAB          bool
	myName        string
	verbose       bool
	quiet         bool
}

func (f *connFlags) register(fs *flag.FlagSet, allowPasswordStdin bool) {
	fs.StringVar(&f.server, "server", "", "server profile (see rdcli server list)")
	fs.StringVar(&f.idServer, "id-server", "", "ID server: host[:port] or ws(s)://host/ws/id (overrides the profile)")
	fs.StringVar(&f.relay, "relay", "", "relay server: host[:port] or ws(s):// URL (default: the one the ID server announces)")
	fs.StringVar(&f.key, "key", "", "server public key, base64 (overrides the profile)")
	fs.StringVar(&f.token, "token", "", "access token for servers that require login (default: from rdcli login; env RDCLI_TOKEN)")
	fs.BoolVar(&f.insecure, "insecure", false, "do not verify TLS certificates of wss:// servers")
	if allowPasswordStdin {
		fs.BoolVar(&f.passwordStdin, "password-stdin", false, "read the device password from the first line of stdin")
	}
	fs.BoolVar(&f.approval, "approval", false, "send no password; wait for the person at the device to accept")
	fs.BoolVar(&f.remember, "remember", false, "remember the password (as the peer's salted hash) in the config file")
	fs.BoolVar(&f.noAB, "no-ab", false, "do not look the device up in the address book for a password")
	fs.StringVar(&f.myName, "name", "", "name shown on the device (default: rdcli (<hostname>))")
	fs.BoolVar(&f.verbose, "v", false, "print protocol details")
	fs.BoolVar(&f.quiet, "q", false, "print no status messages")
}

// Log lines may carry text from the server or the device: sanitized.
func (f *connFlags) logf(format string, a ...any) {
	if !f.quiet {
		fmt.Fprint(os.Stderr, "rdcli: "+term.Sanitize(fmt.Sprintf(format, a...))+"\r\n")
	}
}

func (f *connFlags) debugf(format string, a ...any) {
	if f.verbose {
		fmt.Fprint(os.Stderr, "rdcli: "+term.Sanitize(fmt.Sprintf(format, a...))+"\r\n")
	}
}

// target is a resolved connection: server, peer and login secrets.
type target struct {
	cfg        *config.Config
	serverName string
	profile    *config.Server
	server     rendezvous.Server
	peerID     string
	password   string
	hash       []byte
	// hashFromConfig: hash is the remembered one (rdcli --remember earlier).
	hashFromConfig bool
	flags          *connFlags
}

// resolve builds the server settings and the peer id from flags, env and
// the config file.
func (f *connFlags) resolve(peerArg string) (*target, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	name, prof, err := cfg.Server(f.server)
	if err != nil {
		return nil, err
	}
	id, p := cfg.ResolvePeer(peerArg)
	if p != nil && p.Server != "" && f.server == "" && f.idServer == "" {
		if n, pr, err := cfg.Server(p.Server); err == nil && pr != nil {
			name, prof = n, pr
		}
	}
	t := &target{cfg: cfg, serverName: name, profile: prof, peerID: peer.NormalizeID(id), flags: f}
	if prof != nil {
		t.server = rendezvous.Server{IDServer: prof.IDServer, Relay: prof.Relay, Key: prof.Key, Token: prof.Token, Insecure: prof.Insecure}
	}
	pick := func(dst *string, flagVal, env string) {
		if flagVal != "" {
			*dst = flagVal
		} else if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
	profileID := t.server.IDServer
	pick(&t.server.IDServer, f.idServer, "RDCLI_ID_SERVER")
	// The profile's token belongs to the profile's server: never hand it to
	// another ID server named on the command line or in the environment.
	if t.server.IDServer != profileID {
		t.server.Token = ""
	}
	pick(&t.server.Relay, f.relay, "RDCLI_RELAY")
	pick(&t.server.Key, f.key, "RDCLI_KEY")
	pick(&t.server.Token, f.token, "RDCLI_TOKEN")
	t.server.Insecure = t.server.Insecure || f.insecure
	if t.server.IDServer == "" {
		return nil, usagef("no server configured: run rdcli server import (from an installed RustDesk) or rdcli server add, or pass --id-server and --key")
	}
	if t.server.Key == "" {
		return nil, usagef("no server key: rdcli refuses to connect without it (the device's identity could not be verified); pass --key or set it in the profile")
	}
	if t.peerID == "" {
		return nil, usagef("missing device id")
	}
	return t, nil
}

// secrets gathers the password sources in order: --password-stdin,
// RDCLI_PASSWORD, the remembered hash, the address book.
func (t *target) secrets(ctx context.Context) error {
	f := t.flags
	if f.approval {
		return nil
	}
	if f.passwordStdin {
		pw, err := term.ReadPasswordStdin()
		if err != nil {
			return err
		}
		t.password = pw
		return nil
	}
	if pw := os.Getenv("RDCLI_PASSWORD"); pw != "" {
		t.password = pw
		return nil
	}
	if h := t.cfg.RememberedHash(t.peerID); h != nil {
		t.hashFromConfig = true
		t.hash = h
		return nil
	}
	if f.noAB || t.profile == nil || t.profile.API == "" || t.server.Token == "" {
		return nil
	}
	c := t.apiClient()
	actx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	peers, err := c.AllPeers(actx)
	if err != nil {
		f.debugf("address book: %v", err)
	}
	for _, p := range peers {
		if p.ID != t.peerID {
			continue
		}
		if p.Hash != "" {
			if h, err := base64.StdEncoding.DecodeString(p.Hash); err == nil && len(h) == 32 {
				t.hash = h
			}
		}
		if p.Password != "" {
			t.password = p.Password
		}
		if t.hash != nil || t.password != "" {
			f.debugf("using the password from address book %q", p.Book)
			break
		}
	}
	return nil
}

func (t *target) apiClient() *api.Client {
	c := &api.Client{Token: t.server.Token}
	if t.profile != nil {
		c.Base, c.ID, c.UUID = t.profile.API, t.profile.MyID, t.profile.UUID
	}
	return c
}

func (t *target) myName() string {
	if t.flags.myName != "" {
		return t.flags.myName
	}
	if h := hostname(); h != "" {
		return "rdcli (" + h + ")"
	}
	return "rdcli"
}

func (t *target) myID() string {
	if t.profile != nil && t.profile.MyID != "" {
		return t.profile.MyID
	}
	return "rdcli"
}

// connect logs in for one session kind.
func (t *target) connect(ctx context.Context, connType pb.ConnType, login func(*pb.LoginRequest), loginCode func(string) peer.Code) (*peer.Session, error) {
	f := t.flags
	prompter := &term.Prompter{PeerID: t.peerID, Quiet: f.quiet}
	if f.passwordStdin || os.Getenv("RDCLI_PASSWORD") != "" {
		prompter.NoRetry = true
	}
	f.debugf("connecting to %s via %s", t.peerID, t.server.IDServer)
	s, err := peer.Connect(ctx, peer.Options{
		Server:          t.server,
		PeerID:          t.peerID,
		ConnType:        connType,
		Login:           login,
		Password:        t.password,
		RememberedHash:  t.hash,
		RequestApproval: f.approval,
		Prompter:        prompter,
		MyID:            t.myID(),
		MyName:          t.myName(),
		MyPlatform:      platformName(),
		LoginErrorCode:  loginCode,
		Debugf:          f.debugf,
	})
	if err != nil {
		var pe *peer.Error
		if t.hash != nil && errors.As(err, &pe) && pe.Code == peer.CodeWrongPassword && t.cfg.Forget(t.peerID) {
			t.cfg.Save()
			f.logf("the remembered password no longer works and was forgotten")
		}
		return nil, err
	}
	if pi := s.PeerInfo; pi != nil {
		f.debugf("logged in to %s@%s (%s, RustDesk %s, key exchange v%d)", pi.GetUsername(), pi.GetHostname(), pi.GetPlatform(), pi.GetVersion(), s.KxVersion)
	}
	// Later logins (legacy forwarding, a new tunnel) reuse what worked.
	if s.Hash != nil {
		t.hash = append([]byte(nil), s.Hash...)
		t.password = ""
		// A password remembered earlier that was just replaced at the prompt
		// is updated too: the user chose to remember this device.
		if old := t.cfg.RememberedHash(t.peerID); t.hashFromConfig && old != nil && string(old) != string(s.Hash) {
			f.remember = true
		}
		if f.remember {
			t.cfg.Remember(t.peerID, t.serverName, s.Hash)
			if err := t.cfg.Save(); err != nil {
				f.logf("cannot save the password: %v", err)
			} else {
				f.debugf("password remembered in %s", t.cfg.File())
			}
		}
	}
	return s, nil
}

func splitPeerPath(arg string) (peerPart, path string, remote bool) {
	// Windows local paths have a drive letter: C:\x is local.
	if len(arg) >= 2 && arg[1] == ':' && (len(arg) == 2 || arg[2] == '\\' || arg[2] == '/') {
		return "", arg, false
	}
	i := strings.IndexByte(arg, ':')
	if i <= 0 {
		return "", arg, false
	}
	return arg[:i], arg[i+1:], true
}
