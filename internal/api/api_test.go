package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// panel mimics RD Panel's client API (internal/clientapi): password, then a
// TOTP challenge; the address book behind a bearer token.
func panel(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var req loginRequest
		json.NewDecoder(r.Body).Decode(&req)
		switch req.Type {
		case "account":
			if req.Username != "alice" || req.Password != "pw" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid username or password"})
				return
			}
			json.NewEncoder(w).Encode(authBody{Type: "email_check", TfaType: "tfa_check", Secret: "sealed"})
		case "tfa_code":
			if req.Secret != "sealed" || req.TfaCode != "123456" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "Wrong code"})
				return
			}
			json.NewEncoder(w).Encode(authBody{Type: "access_token", AccessToken: "tok", User: &User{Name: "alice"}})
		}
	})
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token"})
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("POST /api/ab/personal", auth(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"guid": "g-personal"})
	}))
	mux.HandleFunc("POST /api/ab/shared/profiles", auth(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(page[Book]{Total: 1, Data: []Book{{GUID: "g-team", Name: "Team"}}})
	}))
	mux.HandleFunc("POST /api/ab/peers", auth(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("ab") {
		case "g-personal":
			json.NewEncoder(w).Encode(page[Peer]{Total: 1, Data: []Peer{{ID: "111", Alias: "home", Hash: "aGFzaA=="}}})
		case "g-team":
			json.NewEncoder(w).Encode(page[Peer]{Total: 1, Data: []Peer{{ID: "222", Password: "shared"}}})
		}
	}))
	mux.HandleFunc("POST /api/logout", auth(func(w http.ResponseWriter, r *http.Request) {}))
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func TestLoginWithTOTPAndAddressBook(t *testing.T) {
	s := panel(t)
	c := &Client{Base: s.URL, UUID: "u"}
	ctx := context.Background()
	if _, err := c.Login(ctx, LoginOptions{Username: "alice", Password: "bad"}); err == nil {
		t.Fatal("bad password accepted")
	}
	codes := []string{"000000", "123456"}
	u, err := c.Login(ctx, LoginOptions{Username: "alice", Password: "pw", Code: func(kind string, wrong bool) (string, error) {
		if kind != "totp" {
			t.Fatalf("kind %q", kind)
		}
		code := codes[0]
		codes = codes[1:]
		return code, nil
	}})
	if err != nil || c.Token != "tok" || u.Name != "alice" {
		t.Fatalf("login: %v token %q", err, c.Token)
	}
	peers, err := c.AllPeers(ctx)
	if err != nil || len(peers) != 2 || peers[0].Book != "My address book" || peers[1].Password != "shared" {
		t.Fatalf("peers %+v %v", peers, err)
	}
	if err := c.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	c.Token = "expired"
	if _, err := c.AllPeers(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired token: %v", err)
	}
}
