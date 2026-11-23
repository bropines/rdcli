// Package e2e runs rdcli's connection code against the in-process fake
// server and peer (internal/testpeer).
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bropines/rdcli/internal/forward"
	"github.com/bropines/rdcli/internal/pb"
	"github.com/bropines/rdcli/internal/peer"
	"github.com/bropines/rdcli/internal/rendezvous"
	"github.com/bropines/rdcli/internal/testpeer"
)

type scripted struct {
	passwords []string
	codes     []string
	statuses  []string
	mu        sync.Mutex
}

func (s *scripted) Password(wrong bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.passwords) == 0 {
		return "", errors.New("no more passwords")
	}
	p := s.passwords[0]
	s.passwords = s.passwords[1:]
	return p, nil
}

func (s *scripted) TwoFactor(wrong bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.codes) == 0 {
		return "", errors.New("no more codes")
	}
	c := s.codes[0]
	s.codes = s.codes[1:]
	return c, nil
}

func (s *scripted) Status(msg string) {
	s.mu.Lock()
	s.statuses = append(s.statuses, msg)
	s.mu.Unlock()
}

func opts(srv *testpeer.Server, ct pb.ConnType, login func(*pb.LoginRequest)) peer.Options {
	return peer.Options{
		Server:   rendezvous.Server{IDServer: srv.IDServer(), Key: srv.Key},
		PeerID:   "123 456 789",
		ConnType: ct,
		Login:    login,
		MyID:     "rdcli", MyName: "test", MyPlatform: "Linux",
	}
}

func termLogin(lr *pb.LoginRequest) { lr.Union = &pb.LoginRequest_Terminal{Terminal: &pb.Terminal{}} }

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func expectTerm(t *testing.T, s *peer.Session, want string) {
	t.Helper()
	var got strings.Builder
	for !strings.Contains(got.String(), want) {
		m, err := s.Recv()
		if err != nil {
			t.Fatalf("waiting for %q (got %q): %v", want, got.String(), err)
		}
		if d := m.GetTerminalResponse().GetData(); d != nil {
			got.Write(d.Data)
		}
	}
}

func TestTerminalAllKeyExchangeVersions(t *testing.T) {
	for _, c := range []struct{ server, peer bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprintf("hbbs-v1=%v/peer-v1=%v", c.server, c.peer), func(t *testing.T) {
			srv := testpeer.Start(t, testpeer.Options{Password: "pw", ServerKxV1: c.server, PeerKxV1: c.peer})
			o := opts(srv, pb.ConnType_TERMINAL, termLogin)
			o.Password = "pw"
			s, err := peer.Connect(ctx(t), o)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close("")
			wantKx := uint32(0)
			if c.peer {
				wantKx = 1
			}
			if s.KxVersion != wantKx || srv.KxVersions[0] != wantKx {
				t.Fatalf("peer kx: ours v%d, peer saw v%d, want v%d", s.KxVersion, srv.KxVersions[0], wantKx)
			}
			wantSrv := uint32(0)
			if c.server {
				wantSrv = 1
			}
			if len(srv.ServerKxVersions) != 1 || srv.ServerKxVersions[0] != wantSrv {
				t.Fatalf("hbbs kx %v, want v%d", srv.ServerKxVersions, wantSrv)
			}
			if s.PeerInfo.GetHostname() != "box" {
				t.Fatalf("peer info %v", s.PeerInfo)
			}
			send := func(a *pb.TerminalAction) {
				if err := s.Send(&pb.Message{Union: &pb.Message_TerminalAction{TerminalAction: a}}); err != nil {
					t.Fatal(err)
				}
			}
			send(&pb.TerminalAction{Union: &pb.TerminalAction_Open{Open: &pb.OpenTerminal{Cols: 100, Rows: 30}}})
			expectTerm(t, s, "size 100x30")
			send(&pb.TerminalAction{Union: &pb.TerminalAction_Data{Data: &pb.TerminalData{Data: []byte("hello\n")}}})
			expectTerm(t, s, "HELLO")
			send(&pb.TerminalAction{Union: &pb.TerminalAction_Data{Data: &pb.TerminalData{Data: []byte("exit\n")}}})
			for {
				m, err := s.Recv()
				if err != nil {
					t.Fatal(err)
				}
				if cl := m.GetTerminalResponse().GetClosed(); cl != nil {
					if cl.ExitCode != 3 {
						t.Fatalf("exit code %d", cl.ExitCode)
					}
					return
				}
			}
		})
	}
}

func TestSameLANFallsBackToClientRelay(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "pw", SameLAN: true, ServerKxV1: true})
	o := opts(srv, pb.ConnType_TERMINAL, termLogin)
	o.Password = "pw"
	s, err := peer.Connect(ctx(t), o)
	if err != nil {
		t.Fatal(err)
	}
	s.Close("")
	if srv.ClientRelays != 1 || len(srv.ServerKxVersions) != 2 {
		t.Fatalf("client relays %d, hbbs key exchanges %v", srv.ClientRelays, srv.ServerKxVersions)
	}
}

func TestWrongPasswordThenRight(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "right"})
	p := &scripted{passwords: []string{"wrong", "right"}}
	o := opts(srv, pb.ConnType_TERMINAL, termLogin)
	o.Prompter = p
	s, err := peer.Connect(ctx(t), o)
	if err != nil {
		t.Fatal(err)
	}
	s.Close("")
	if len(p.passwords) != 0 || s.Hash == nil {
		t.Fatal("did not retry with the second password")
	}
	// The remembered hash logs in without asking.
	o.Prompter = &scripted{}
	o.RememberedHash = s.Hash
	s2, err := peer.Connect(ctx(t), o)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close("")
}

func TestScriptedWrongPasswordFails(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "right"})
	o := opts(srv, pb.ConnType_TERMINAL, termLogin)
	o.Password = "wrong"
	_, err := peer.Connect(ctx(t), o)
	var pe *peer.Error
	if !errors.As(err, &pe) || pe.Code != peer.CodeWrongPassword {
		t.Fatalf("got %v", err)
	}
}

func TestTwoFactor(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "pw", TwoFA: "123456"})
	o := opts(srv, pb.ConnType_TERMINAL, termLogin)
	o.Password = "pw"
	o.Prompter = &scripted{codes: []string{"000000", "123456"}}
	s, err := peer.Connect(ctx(t), o)
	if err != nil {
		t.Fatal(err)
	}
	s.Close("")
}

func TestRequestApproval(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "pw", ClickOnly: true, ApproveAfter: 300 * time.Millisecond})
	o := opts(srv, pb.ConnType_TERMINAL, termLogin)
	o.Password = "pw" // must not be sent
	o.RequestApproval = true
	p := &scripted{}
	o.Prompter = p
	s, err := peer.Connect(ctx(t), o)
	if err != nil {
		t.Fatal(err)
	}
	s.Close("")
	if s.Hash != nil || len(p.statuses) == 0 {
		t.Fatalf("hash %x statuses %v", s.Hash, p.statuses)
	}
}

func TestApprovalTimeout(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{ClickOnly: true, ApproveAfter: 5 * time.Second})
	o := opts(srv, pb.ConnType_TERMINAL, termLogin)
	o.RequestApproval = true
	o.ApprovalTimeout = 300 * time.Millisecond
	_, err := peer.Connect(ctx(t), o)
	var pe *peer.Error
	if !errors.As(err, &pe) || pe.Code != peer.CodeApprovalTimeout {
		t.Fatalf("got %v", err)
	}
}

func TestTokenAndOffline(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "pw", RequireTok: "tok"})
	o := opts(srv, pb.ConnType_TERMINAL, termLogin)
	o.Password = "pw"
	_, err := peer.Connect(ctx(t), o)
	var re *rendezvous.Error
	if !errors.As(err, &re) || re.Code != rendezvous.CodeLoginRequired {
		t.Fatalf("without token: %v", err)
	}
	o.Server.Token = "tok"
	s, err := peer.Connect(ctx(t), o)
	if err != nil {
		t.Fatal(err)
	}
	s.Close("")

	// A token never goes out in the clear.
	plain := testpeer.Start(t, testpeer.Options{Password: "pw", NoServerKX: true})
	o = opts(plain, pb.ConnType_TERMINAL, termLogin)
	o.Password, o.Server.Token = "pw", "tok"
	if _, err := peer.Connect(ctx(t), o); !errors.As(err, &re) || re.Code != rendezvous.CodeInsecure {
		t.Fatalf("token over a plain connection: %v", err)
	}
	// Without a token a keyless server is fine.
	o.Server.Token = ""
	if s, err := peer.Connect(ctx(t), o); err != nil {
		t.Fatalf("keyless server: %v", err)
	} else {
		s.Close("")
	}

	off := testpeer.Start(t, testpeer.Options{Offline: true})
	if _, err := peer.Connect(ctx(t), opts(off, pb.ConnType_TERMINAL, termLogin)); !errors.As(err, &re) || re.Code != rendezvous.CodeOffline {
		t.Fatalf("offline: %v", err)
	}
	o = opts(srv, pb.ConnType_TERMINAL, termLogin)
	o.PeerID = "999"
	o.Server.Token = "tok"
	if _, err := peer.Connect(ctx(t), o); !errors.As(err, &re) || re.Code != rendezvous.CodeNotFound {
		t.Fatalf("unknown id: %v", err)
	}
	o = opts(srv, pb.ConnType_TERMINAL, termLogin)
	o.Server.Key = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw="
	if _, err := peer.Connect(ctx(t), o); err == nil {
		t.Fatal("wrong server key accepted")
	}
}

func dialer(srv *testpeer.Server) forward.Dialer {
	return func(c context.Context, tg forward.Target, mux bool) (*peer.Session, error) {
		o := opts(srv, pb.ConnType_PORT_FORWARD, forward.LoginFields(tg, mux))
		o.Password = "pw"
		return peer.Connect(c, o)
	}
}

func echoThrough(t *testing.T, addr string, size int) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := make([]byte, size)
	rand.Read(payload)
	go func() { c.Write(payload) }()
	got := make([]byte, size)
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("echo of %d bytes: %v", size, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo differs")
	}
}

func runMapping(t *testing.T, srv *testpeer.Server, mode forward.Mode) (string, *forward.Mapping) {
	echo := testpeer.EchoServer(t)
	host, port, _ := net.SplitHostPort(echo)
	var p int32
	fmt.Sscan(port, &p)
	m := &forward.Mapping{Target: forward.Target{Host: host, Port: p}, Dial: dialer(srv), Mode: mode, Logf: t.Logf}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	bind := ln.Addr().String()
	ln.Close()
	c, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Listen(c, bind); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 50; i++ {
		if conn, err := net.Dial("tcp", bind); err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return bind, m
}

func TestForwardMultiplexed(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "pw", Mux: true})
	bind, _ := runMapping(t, srv, forward.ModeAuto)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			echoThrough(t, bind, 100+i*700_000) // up to ~2 MB, well past the windows
		}(i)
	}
	wg.Wait()
	echoThrough(t, bind, 10)
	// one probe connection from runMapping + 5; all on one login
	if srv.Logins != 1 {
		t.Fatalf("%d logins for a multiplexed mapping, want 1", srv.Logins)
	}
}

func TestForwardLegacy(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "pw", Mux: false})
	bind, _ := runMapping(t, srv, forward.ModeAuto)
	echoThrough(t, bind, 300_000)
	echoThrough(t, bind, 5)
	if srv.Logins < 2 {
		t.Fatalf("%d logins, want one per connection", srv.Logins)
	}
}

func TestForwardRequireMux(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "pw", Mux: false})
	m := &forward.Mapping{Target: forward.Target{Host: "127.0.0.1", Port: 1}, Dial: dialer(srv), Mode: forward.ModeMux}
	a, b := net.Pipe()
	defer b.Close()
	if err := m.Serve(ctx(t), a); err == nil || !strings.Contains(err.Error(), "multiplexed") {
		t.Fatalf("got %v", err)
	}
}

func TestForwardRefusedTarget(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "pw", Mux: true})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	m := &forward.Mapping{Target: forward.Target{Host: "127.0.0.1", Port: int32(dead)}, Dial: dialer(srv)}
	a, b := net.Pipe()
	defer b.Close()
	err := m.Serve(ctx(t), a)
	if err == nil {
		t.Fatal("a refused target served")
	}
}

// The device closes the channel right after its data while we still upload:
// everything it sent must reach the local side before the close.
func TestForwardPeerCloseDeliversQueuedData(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "pw", Mux: true})
	burst := testpeer.BurstServer(t, 200_000)
	host, port, _ := net.SplitHostPort(burst)
	var p int32
	fmt.Sscan(port, &p)
	m := &forward.Mapping{Target: forward.Target{Host: host, Port: p}, Dial: dialer(srv)}
	for i := 0; i < 5; i++ {
		a, b := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- m.Serve(ctx(t), a) }()
		stop := make(chan struct{})
		go func() { // keep uploading
			buf := make([]byte, 4096)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := b.Write(buf); err != nil {
					return
				}
			}
		}()
		got, _ := io.Copy(io.Discard, b)
		close(stop)
		b.Close()
		serr := <-done
		t.Logf("round %d: serve returned %v", i, serr)
		if got != 200_000 {
			t.Fatalf("round %d: got %d of 200000 bytes", i, got)
		}
	}
}

type blockingReader struct{ ch chan struct{} }

func (r blockingReader) Read([]byte) (int, error) {
	<-r.ch
	return 0, io.EOF
}
func (r blockingReader) Write(p []byte) (int, error) { return len(p), nil }
func (r blockingReader) Close() error                { return nil }

// rdcli pipe: a stdin read cannot be interrupted, yet cancelling must end
// the channel, in both modes.
func TestForwardCancelWithBlockedStdin(t *testing.T) {
	for _, mux := range []bool{true, false} {
		srv := testpeer.Start(t, testpeer.Options{Password: "pw", Mux: mux})
		echo := testpeer.EchoServer(t)
		host, port, _ := net.SplitHostPort(echo)
		var p int32
		fmt.Sscan(port, &p)
		m := &forward.Mapping{Target: forward.Target{Host: host, Port: p}, Dial: dialer(srv)}
		c, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		r := blockingReader{ch: make(chan struct{})}
		go func() { done <- m.Serve(c, forward.Stdio{In: r, Out: r}) }()
		time.Sleep(500 * time.Millisecond)
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("mux=%v: Serve did not return after cancel", mux)
		}
		close(r.ch)
		m.Close()
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// printf 'request\n' | rdcli pipe: stdin ends at once, the answer must
// still arrive, in both modes. A plain socket gives up after DefaultLinger
// of silence.
func TestPipeAnswerAfterStdinEOF(t *testing.T) {
	forward.DefaultLinger = 100 * time.Millisecond
	defer func() { forward.DefaultLinger = 10 * time.Second }()
	for _, mux := range []bool{true, false} {
		srv := testpeer.Start(t, testpeer.Options{Password: "pw", Mux: mux})
		target := testpeer.ReplyServer(t, "the answer", 600*time.Millisecond)
		host, port, _ := net.SplitHostPort(target)
		var p int32
		fmt.Sscan(port, &p)
		m := &forward.Mapping{Target: forward.Target{Host: host, Port: p}, Dial: dialer(srv)}
		var out bytes.Buffer
		err := m.Serve(ctx(t), forward.Stdio{In: io.NopCloser(strings.NewReader("request\n")), Out: nopWriteCloser{&out}})
		if err != nil || out.String() != "the answer" {
			t.Fatalf("mux=%v: %v, got %q", mux, err, out.String())
		}
		m.Close()
	}
}

func TestStaleRememberedHashFallsBackToPassword(t *testing.T) {
	srv := testpeer.Start(t, testpeer.Options{Password: "pw"})
	o := opts(srv, pb.ConnType_TERMINAL, termLogin)
	o.RememberedHash = bytes.Repeat([]byte{7}, 32)
	o.Password = "pw"
	s, err := peer.Connect(ctx(t), o)
	if err != nil {
		t.Fatal(err)
	}
	s.Close("")
}

func TestNoTokenOverPlainWebSocket(t *testing.T) {
	_, err := rendezvous.RequestRelay(ctx(t), rendezvous.Request{
		Server: rendezvous.Server{IDServer: "ws://127.0.0.1:1/ws/id", Key: "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=", Token: "tok"},
		PeerID: "1",
	})
	var re *rendezvous.Error
	if !errors.As(err, &re) || re.Code != rendezvous.CodeInsecure {
		t.Fatalf("got %v", err)
	}
}
