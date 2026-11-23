package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/bropines/rdcli/internal/crypto"
)

// ParseConfigString decodes the server config string the RustDesk client
// exports and imports (Settings > Network): base64 of
// {"host","relay","api","key"} JSON, written backwards.
func ParseConfigString(s string) (*Server, error) {
	s = strings.TrimSpace(s)
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(string(r), "="))
	if err != nil {
		return nil, errors.New("not a RustDesk config string")
	}
	var v struct {
		Host  string `json:"host"`
		Relay string `json:"relay"`
		API   string `json:"api"`
		Key   string `json:"key"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, errors.New("not a RustDesk config string")
	}
	if v.Host == "" || v.Key == "" {
		return nil, errors.New("the config string has no ID server or key")
	}
	if _, err := crypto.ParseServerKey(v.Key); err != nil {
		return nil, err
	}
	return &Server{IDServer: v.Host, Relay: v.Relay, API: v.API, Key: v.Key}, nil
}
