package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/bropines/rdcli/internal/pb"
	"github.com/bropines/rdcli/internal/peer"
)

// Target is the address the device connects to.
type Target struct {
	Host string
	Port int32
}

func (t Target) String() string { return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port))) }

// LoginFields returns the LoginRequest fields of a port-forward session.
func LoginFields(t Target, multiplex bool) func(*pb.LoginRequest) {
	return func(lr *pb.LoginRequest) {
		lr.Union = &pb.LoginRequest_PortForward{PortForward: &pb.PortForward{Host: t.Host, Port: t.Port, Multiplex: multiplex}}
	}
}

// LoginErrorCode classifies a port-forward login refusal.
func LoginErrorCode(e string) peer.Code {
	l := strings.ToLower(e)
	if strings.Contains(l, "no permission") || strings.Contains(l, "tunnel") && strings.Contains(l, "disabled") {
		return peer.CodePermissionDenied
	}
	return peer.CodeLogin
}

// Dialer connects and logs in for a port-forward session to t.
type Dialer func(ctx context.Context, t Target, multiplex bool) (*peer.Session, error)

// Mode is how a mapping reaches the device.
type Mode int

const (
	ModeAuto Mode = iota
	ModeMux
	ModeLegacy
)

// Mapping serves connections for one target, sharing one tunnel when the
// peer supports multiplexing.
type Mapping struct {
	Target Target
	Dial   Dialer
	Mode   Mode
	// Logf reports events (connections, refusals, mode).
	Logf func(format string, a ...any)
	// Insecure is called once when the legacy (unencrypted) mode is picked.
	OnLegacy func()

	mu        sync.Mutex
	tunnel    *Tunnel
	legacy    bool
	connect   sync.Mutex
	warnedRaw bool
}

func (m *Mapping) logf(format string, a ...any) {
	if m.Logf != nil {
		m.Logf(format, a...)
	}
}

// Serve runs one local connection to completion.
func (m *Mapping) Serve(ctx context.Context, local io.ReadWriteCloser) error {
	for attempt := 0; attempt < 2; attempt++ {
		t, sess, err := m.channel(ctx)
		if err != nil {
			local.Close()
			return err
		}
		if t == nil {
			return m.runLegacy(ctx, sess, local)
		}
		err = t.Serve(ctx, local)
		if errors.Is(err, ErrTunnelGone) {
			continue // the tunnel ended under us: establish a new one
		}
		return err
	}
	local.Close()
	return ErrTunnelGone
}

// channel returns the live tunnel, or a fresh legacy session for this one
// connection.
func (m *Mapping) channel(ctx context.Context) (*Tunnel, *peer.Session, error) {
	m.connect.Lock()
	defer m.connect.Unlock()
	m.mu.Lock()
	t, legacy := m.tunnel, m.legacy
	m.mu.Unlock()
	if t != nil {
		select {
		case <-t.Done():
			m.logf("tunnel to %s ended: %v", m.Target, t.Err())
		default:
			return t, nil, nil
		}
	}
	mux := m.Mode != ModeLegacy && !legacy
	s, err := m.Dial(ctx, m.Target, mux)
	if err != nil {
		return nil, nil, err
	}
	if mux {
		if f := s.Features(); f != nil && f.GetPortForwardMux() {
			t := NewTunnel(s, m.Target.Host, m.Target.Port, func(msg string) { m.logf("%s: %s", m.Target, msg) })
			m.mu.Lock()
			m.tunnel = t
			m.mu.Unlock()
			m.logf("multiplexed tunnel to %s is up", m.Target)
			return t, nil, nil
		}
		if m.Mode == ModeMux {
			s.Close("multiplexing unsupported")
			return nil, nil, errors.New("the device does not support multiplexed port forwarding (RustDesk 1.5+); use --legacy")
		}
		m.mu.Lock()
		m.legacy = true
		m.mu.Unlock()
	}
	// hbbr pipes raw bytes only between two TCP legs; over a WebSocket relay
	// the device's unframed bytes would be parsed as frames and corrupted.
	if strings.HasPrefix(s.Relay, "ws://") || strings.HasPrefix(s.Relay, "wss://") {
		s.Close("legacy forwarding needs a TCP relay")
		return nil, nil, errors.New("the device has no multiplexed forwarding (RustDesk 1.5+), and the legacy mode does not work through a WebSocket relay; use a TCP relay (--relay host:21117)")
	}
	if !m.warnedRaw {
		m.warnedRaw = true
		if m.OnLegacy != nil {
			m.OnLegacy()
		}
	}
	return nil, s, nil
}

// runLegacy pipes plain bytes, the way RustDesk forwards for peers without
// multiplexing: framing and encryption end with the login.
func (m *Mapping) runLegacy(ctx context.Context, s *peer.Session, local io.ReadWriteCloser) error {
	s.SetRaw()
	done := make(chan error, 2)
	stop := context.AfterFunc(ctx, func() { s.Close(""); local.Close() })
	defer stop()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				if werr := s.SendRaw(append([]byte(nil), buf[:n]...)); werr != nil {
					done <- werr
					return
				}
			}
			if err != nil {
				done <- nil
				return
			}
		}
	}()
	go func() {
		for {
			b, err := s.RecvRaw()
			if len(b) > 0 {
				if _, werr := local.Write(b); werr != nil {
					done <- nil
					return
				}
			}
			if err != nil {
				done <- nil
				return
			}
		}
	}()
	// The first half to end ends both. The other one is not waited for: a
	// read from stdin (rdcli pipe) cannot be interrupted.
	err := <-done
	s.Close("")
	local.Close()
	return err
}

// Close ends the shared tunnel.
func (m *Mapping) Close() {
	m.mu.Lock()
	t := m.tunnel
	m.tunnel = nil
	m.mu.Unlock()
	if t != nil {
		t.Close()
	}
}

// Listen accepts on bind and serves each connection until ctx ends.
func (m *Mapping) Listen(ctx context.Context, bind string) error {
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return err
	}
	m.logf("forwarding %s -> %s on the device", ln.Addr(), m.Target)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				m.Close()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Serve(ctx, c); err != nil && ctx.Err() == nil {
				m.logf("%s: %v", c.RemoteAddr(), err)
			}
		}()
	}
}

// Spec is one -L option: [bind_address:]port:host:hostport.
type Spec struct {
	Bind   string
	Target Target
}

// ParseSpec parses [bind:]port:host:hostport (IPv6 in brackets). A missing
// host means the device itself (localhost).
func ParseSpec(s string) (Spec, error) {
	parts, err := splitColons(s)
	if err != nil {
		return Spec{}, err
	}
	var bindHost, bindPort, host, hostPort string
	switch len(parts) {
	case 2: // port:hostport -> localhost on both ends
		bindPort, hostPort = parts[0], parts[1]
		host = "localhost"
	case 3:
		bindPort, host, hostPort = parts[0], parts[1], parts[2]
	case 4:
		bindHost, bindPort, host, hostPort = parts[0], parts[1], parts[2], parts[3]
	default:
		return Spec{}, fmt.Errorf("bad forward %q: want [bind:]port:host:hostport", s)
	}
	if bindHost == "" {
		bindHost = "127.0.0.1"
	}
	if host == "" {
		host = "localhost"
	}
	if _, err := strconv.ParseUint(bindPort, 10, 16); err != nil {
		return Spec{}, fmt.Errorf("bad local port %q", bindPort)
	}
	p, err := strconv.ParseUint(hostPort, 10, 16)
	if err != nil || p == 0 {
		return Spec{}, fmt.Errorf("bad remote port %q", hostPort)
	}
	return Spec{Bind: net.JoinHostPort(bindHost, bindPort), Target: Target{Host: host, Port: int32(p)}}, nil
}

// ParseTarget parses host:port (or just a port, meaning the device itself).
func ParseTarget(s string) (Target, error) {
	if p, err := strconv.ParseUint(s, 10, 16); err == nil && p > 0 {
		return Target{Host: "localhost", Port: int32(p)}, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return Target{}, fmt.Errorf("bad target %q: want host:port", s)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return Target{}, fmt.Errorf("bad port in %q", s)
	}
	if host == "" {
		host = "localhost"
	}
	return Target{Host: host, Port: int32(p)}, nil
}

func splitColons(s string) ([]string, error) {
	var parts []string
	for len(s) > 0 {
		if s[0] == '[' {
			end := strings.IndexByte(s, ']')
			if end < 0 {
				return nil, fmt.Errorf("unclosed [ in %q", s)
			}
			parts = append(parts, s[1:end])
			s = s[end+1:]
			if s != "" {
				if s[0] != ':' {
					return nil, fmt.Errorf("expected : after ] in forward spec")
				}
				s = s[1:]
			}
			continue
		}
		i := strings.IndexByte(s, ':')
		if i < 0 {
			parts = append(parts, s)
			break
		}
		parts = append(parts, s[:i])
		s = s[i+1:]
	}
	return parts, nil
}

// Stdio is stdin/stdout as one connection (rdcli pipe).
type Stdio struct {
	In  io.ReadCloser
	Out io.WriteCloser
}

func (s Stdio) Read(p []byte) (int, error)  { return s.In.Read(p) }
func (s Stdio) Write(p []byte) (int, error) { return s.Out.Write(p) }
func (s Stdio) Close() error {
	s.Out.Close()
	return s.In.Close()
}
