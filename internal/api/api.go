// Package api talks to the RustDesk API server (RD Panel or any server with
// the RustDesk client API): login, logout and the address book.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is an API server client.
type Client struct {
	Base  string // https://panel.example.com
	Token string
	ID    string // our device id towards the API (may be empty)
	UUID  string
	HTTP  *http.Client
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// Error is an API refusal.
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// ErrUnauthorized means the token is missing, expired or revoked.
var ErrUnauthorized = errors.New("not signed in or the session expired (run rdcli login)")

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.Base, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "rdcli")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	var e struct {
		Error string `json:"error"`
	}
	json.Unmarshal(data, &e)
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return &Error{Status: resp.StatusCode, Msg: e.Error}
	}
	if e.Error != "" {
		if strings.Contains(strings.ToLower(e.Error), "invalid token") || strings.Contains(strings.ToLower(e.Error), "not logged") {
			return ErrUnauthorized
		}
		return &Error{Status: resp.StatusCode, Msg: e.Error}
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// User is the signed-in user.
type User struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	IsAdmin     bool   `json:"is_admin"`
	Status      int    `json:"status"`
}

type authBody struct {
	Type        string `json:"type"`
	AccessToken string `json:"access_token"`
	TfaType     string `json:"tfa_type"`
	Secret      string `json:"secret"`
	User        *User  `json:"user"`
}

type deviceInfo struct {
	OS   string `json:"os"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type loginRequest struct {
	Username         string     `json:"username"`
	Password         string     `json:"password,omitempty"`
	ID               string     `json:"id"`
	UUID             string     `json:"uuid"`
	AutoLogin        bool       `json:"autoLogin"`
	Type             string     `json:"type"`
	TfaCode          string     `json:"tfaCode,omitempty"`
	VerificationCode string     `json:"verificationCode,omitempty"`
	Secret           string     `json:"secret,omitempty"`
	DeviceInfo       deviceInfo `json:"deviceInfo"`
}

// SecondFactor asks for a code: kind is "totp" or "email".
type SecondFactor func(kind string, wrong bool) (string, error)

// LoginOptions for Login.
type LoginOptions struct {
	Username, Password string
	OS, DeviceName     string
	Code               SecondFactor
}

// Login signs in with a password (and a second factor when asked) and
// stores the token on the client.
func (c *Client) Login(ctx context.Context, o LoginOptions) (*User, error) {
	base := loginRequest{
		Username: o.Username, ID: c.ID, UUID: c.UUID, AutoLogin: true,
		DeviceInfo: deviceInfo{OS: o.OS, Type: "client", Name: o.DeviceName},
	}
	req := base
	req.Type = "account"
	req.Password = o.Password
	var body authBody
	if err := c.post(ctx, "/api/login", req, &body); err != nil {
		return nil, err
	}
	for attempt := 0; body.Type != "access_token"; attempt++ {
		if attempt >= 5 {
			return nil, errors.New("too many wrong codes")
		}
		kind, typ := "", ""
		switch {
		case body.Type == "email_check" && body.TfaType == "tfa_check":
			kind, typ = "totp", "tfa_code"
		case body.Type == "email_check":
			kind, typ = "email", "email_code"
		default:
			return nil, fmt.Errorf("unexpected login answer %q", body.Type)
		}
		if o.Code == nil {
			return nil, fmt.Errorf("the account needs a %s code", kind)
		}
		secret := body.Secret
		code, err := o.Code(kind, attempt > 0)
		if err != nil {
			return nil, err
		}
		req = base
		req.Type = typ
		req.Secret = secret
		if typ == "tfa_code" {
			req.TfaCode = code
		} else {
			req.VerificationCode = code
		}
		body = authBody{}
		err = c.post(ctx, "/api/login", req, &body)
		var ae *Error
		if errors.As(err, &ae) && ae.Status == http.StatusBadRequest && strings.Contains(strings.ToLower(ae.Msg), "code") {
			body = authBody{Type: "email_check", TfaType: map[string]string{"totp": "tfa_check", "email": ""}[kind], Secret: secret}
			continue
		}
		if err != nil {
			return nil, err
		}
	}
	if body.AccessToken == "" {
		return nil, errors.New("the server sent no access token")
	}
	c.Token = body.AccessToken
	return body.User, nil
}

// Logout revokes the token.
func (c *Client) Logout(ctx context.Context) error {
	return c.post(ctx, "/api/logout", map[string]string{"id": c.ID, "uuid": c.UUID}, nil)
}

// CurrentUser checks the token.
func (c *Client) CurrentUser(ctx context.Context) (*User, error) {
	var u User
	if err := c.post(ctx, "/api/currentUser", map[string]string{"id": c.ID, "uuid": c.UUID}, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// Book is an address book.
type Book struct {
	GUID     string `json:"guid"`
	Name     string `json:"name"`
	Owner    string `json:"owner"`
	Personal bool   `json:"-"`
}

// Peer is an address book entry.
type Peer struct {
	ID       string   `json:"id"`
	Hash     string   `json:"hash"`
	Password string   `json:"password"`
	Username string   `json:"username"`
	Hostname string   `json:"hostname"`
	Platform string   `json:"platform"`
	Alias    string   `json:"alias"`
	Tags     []string `json:"tags"`
	Note     string   `json:"note"`
	Book     string   `json:"-"`
}

type page[T any] struct {
	Total int `json:"total"`
	Data  []T `json:"data"`
}

// Books lists the personal and the shared address books.
func (c *Client) Books(ctx context.Context) ([]Book, error) {
	var personal struct {
		GUID string `json:"guid"`
	}
	if err := c.post(ctx, "/api/ab/personal", nil, &personal); err != nil {
		return nil, err
	}
	books := []Book{{GUID: personal.GUID, Name: "My address book", Personal: true}}
	for p := 1; ; p++ {
		var pg page[Book]
		if err := c.post(ctx, fmt.Sprintf("/api/ab/shared/profiles?current=%d&pageSize=100", p), nil, &pg); err != nil {
			return books, err
		}
		books = append(books, pg.Data...)
		if len(pg.Data) == 0 || len(books)-1 >= pg.Total {
			break
		}
	}
	return books, nil
}

// Peers lists one address book.
func (c *Client) Peers(ctx context.Context, b Book) ([]Peer, error) {
	var out []Peer
	for p := 1; ; p++ {
		var pg page[Peer]
		path := fmt.Sprintf("/api/ab/peers?current=%d&pageSize=100&ab=%s", p, url.QueryEscape(b.GUID))
		if err := c.post(ctx, path, nil, &pg); err != nil {
			return out, err
		}
		for i := range pg.Data {
			pg.Data[i].Book = b.Name
		}
		out = append(out, pg.Data...)
		if len(pg.Data) == 0 || len(out) >= pg.Total {
			break
		}
	}
	return out, nil
}

// AllPeers lists every address book's entries (personal first).
func (c *Client) AllPeers(ctx context.Context) ([]Peer, error) {
	books, err := c.Books(ctx)
	if err != nil && len(books) == 0 {
		return nil, err
	}
	var out []Peer
	for _, b := range books {
		ps, err := c.Peers(ctx, b)
		if err != nil {
			return out, err
		}
		out = append(out, ps...)
	}
	return out, nil
}
