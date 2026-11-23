// Package config stores server profiles, the panel token and remembered
// peer passwords in one JSON file (mode 0600).
package config

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Server is one RustDesk server profile.
type Server struct {
	IDServer string `json:"id_server"`
	Relay    string `json:"relay,omitempty"`
	Key      string `json:"key"`
	API      string `json:"api,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
	// Panel login (rdcli login): the access token and who it belongs to.
	Token string `json:"token,omitempty"`
	User  string `json:"user,omitempty"`
	// Our identity towards the API server and peers.
	MyID string `json:"my_id,omitempty"`
	UUID string `json:"uuid,omitempty"`
}

// Peer is what we remember about one device.
type Peer struct {
	Alias  string `json:"alias,omitempty"`
	Server string `json:"server,omitempty"`
	// Hash is base64 SHA256(password || salt), stored with --remember.
	Hash string `json:"hash,omitempty"`
}

// Config is the whole file.
type Config struct {
	DefaultServer string             `json:"default_server,omitempty"`
	Servers       map[string]*Server `json:"servers,omitempty"`
	Peers         map[string]*Peer   `json:"peers,omitempty"`

	path string
}

// Path is the config file location: $RDCLI_CONFIG, else
// <user config dir>/rdcli/config.json.
func Path() (string, error) {
	if p := os.Getenv("RDCLI_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rdcli", "config.json"), nil
}

// Load reads the config; a missing file is an empty config.
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	c := &Config{path: p}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return c.init(), nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return c.init(), nil
}

func (c *Config) init() *Config {
	if c.Servers == nil {
		c.Servers = map[string]*Server{}
	}
	if c.Peers == nil {
		c.Peers = map[string]*Peer{}
	}
	return c
}

// File is where Save writes.
func (c *Config) File() string { return c.path }

// Save writes the file atomically with mode 0600.
func (c *Config) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".config-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.path)
}

// Server returns the named profile, or the default one for "".
func (c *Config) Server(name string) (string, *Server, error) {
	if name == "" {
		name = c.DefaultServer
	}
	if name == "" && len(c.Servers) == 1 {
		for n := range c.Servers {
			name = n
		}
	}
	if name == "" {
		return "", nil, nil
	}
	s, ok := c.Servers[name]
	if !ok {
		return "", nil, fmt.Errorf("no server profile %q (see rdcli server list)", name)
	}
	return name, s, nil
}

// ServerNames lists profiles, sorted.
func (c *Config) ServerNames() []string {
	names := make([]string, 0, len(c.Servers))
	for n := range c.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ResolvePeer maps an alias to an id; anything else is returned unchanged
// (spaces stripped).
func (c *Config) ResolvePeer(arg string) (string, *Peer) {
	id := strings.Join(strings.Fields(arg), "")
	if p, ok := c.Peers[id]; ok {
		return id, p
	}
	for pid, p := range c.Peers {
		if p.Alias != "" && strings.EqualFold(p.Alias, arg) {
			return pid, p
		}
	}
	return id, nil
}

// RememberedHash returns the stored hash for a peer.
func (c *Config) RememberedHash(id string) []byte {
	p, ok := c.Peers[id]
	if !ok || p.Hash == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(p.Hash)
	if err != nil {
		return nil
	}
	return b
}

// Remember stores a peer's salted password hash.
func (c *Config) Remember(id, server string, hash []byte) {
	p := c.Peers[id]
	if p == nil {
		p = &Peer{}
		c.Peers[id] = p
	}
	p.Hash = base64.StdEncoding.EncodeToString(hash)
	if server != "" {
		p.Server = server
	}
}

// Forget drops a peer's stored hash.
func (c *Config) Forget(id string) bool {
	p, ok := c.Peers[id]
	if !ok || p.Hash == "" {
		return false
	}
	p.Hash = ""
	if p.Alias == "" {
		delete(c.Peers, id)
	}
	return true
}

// RustDeskOptions reads the [options] of an installed RustDesk client's
// RustDesk2.toml (custom-rendezvous-server, relay-server, key, api-server).
func RustDeskOptions(path string) (map[string]string, error) {
	if path == "" {
		path = rustdeskConfigPath()
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	inOptions := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inOptions = line == "[options]"
			continue
		}
		if !inOptions {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out, sc.Err()
}

func rustdeskConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "RustDesk", "config", "RustDesk2.toml")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Preferences", "com.carriez.RustDesk", "RustDesk2.toml")
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "rustdesk", "RustDesk2.toml")
	}
}
