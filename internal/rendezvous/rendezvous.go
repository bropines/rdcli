// Package rendezvous asks hbbs to introduce us to a peer and joins the relay
// pair the peer is put on.
package rendezvous

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/bropines/rdcli/internal/crypto"
	"github.com/bropines/rdcli/internal/pb"
	"github.com/bropines/rdcli/internal/wire"
)

const (
	PortRendezvous = 21116
	PortRelay      = 21117
)

// Server is what a client needs to know about a RustDesk server.
type Server struct {
	// IDServer is host[:port] (TCP) or a ws(s):// URL of hbbs.
	IDServer string
	// Relay overrides the relay: host[:port] or a ws(s):// URL. Empty: the
	// relay hbbs announces (TCP), or /ws/relay next to a WebSocket IDServer.
	Relay string
	// Key is the server's public key (base64). Required: without it the
	// peer's identity cannot be verified.
	Key string
	// Token is the access token from the API server (MUST_LOGIN servers).
	Token string
	// Insecure skips TLS verification for wss:// URLs.
	Insecure bool
}

// Code classifies a rendezvous failure.
type Code string

const (
	CodeOffline       Code = "offline"
	CodeNotFound      Code = "not-found"
	CodeKeyMismatch   Code = "key-mismatch"
	CodeRefused       Code = "refused"
	CodeLoginRequired Code = "login-required"
	CodeTimeout       Code = "timeout"
	CodeNetwork       Code = "network"
	CodeUnreachable   Code = "unreachable"
	CodeInsecure      Code = "insecure"
)

// Error is a rendezvous failure.
type Error struct {
	Code Code
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func fail(code Code, format string, a ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Retryable reports whether trying again later can help.
func Retryable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		switch e.Code {
		case CodeOffline, CodeTimeout, CodeNetwork, CodeUnreachable:
			return true
		}
	}
	return false
}

// Ticket is what hbbs hands out once the peer joined a relay for us.
type Ticket struct {
	UUID          string
	RelayServer   string // host:port as announced
	SignedPeerKey []byte // IdPk of the peer signed by the server key
	PeerVersion   string
}

// Request is one rendezvous.
type Request struct {
	Server   Server
	PeerID   string
	ConnType pb.ConnType
	Version  string
	Timeout  time.Duration
}

// RequestRelay asks hbbs for the peer and waits for the relay answer.
func RequestRelay(ctx context.Context, req Request) (*Ticket, error) {
	// A plain ws:// link is not encrypted, and hbbs runs no key exchange on
	// it unless asked: the access token would travel in the clear.
	if req.Server.Token != "" && strings.HasPrefix(req.Server.IDServer, "ws://") {
		return nil, fail(CodeInsecure, "not sending the access token over unencrypted ws://; use wss:// or TCP (host:21116)")
	}
	serverKey, err := crypto.ParseServerKey(req.Server.Key)
	if err != nil {
		return nil, err
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, err := wire.Dial(dctx, req.Server.IDServer, PortRendezvous, req.Server.Insecure)
	cancel()
	if err != nil {
		return nil, fail(CodeUnreachable, "cannot reach the ID server: %v", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	s := &secureConn{conn: conn}
	if !wire.IsWS(req.Server.IDServer) {
		if err := s.serverKeyExchange(serverKey, req.Server.Token != ""); err != nil {
			return nil, err
		}
	}
	msg := &pb.RendezvousMessage{Union: &pb.RendezvousMessage_PunchHoleRequest{PunchHoleRequest: &pb.PunchHoleRequest{
		Id: req.PeerID,
		// We never accept a hole-punched connection: a symmetric NAT makes
		// the peer meet us on a relay.
		NatType:    pb.NatType_SYMMETRIC,
		LicenceKey: strings.TrimSpace(req.Server.Key),
		ConnType:   req.ConnType,
		Token:      req.Server.Token,
		Version:    req.Version,
		ForceRelay: true,
	}}}
	if err := s.send(msg); err != nil {
		return nil, fail(CodeNetwork, "ID server connection failed: %v", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		conn.SetReadDeadline(deadline)
		in, err := s.recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, fail(CodeTimeout, "the remote device did not answer")
			}
			return nil, fail(CodeNetwork, "ID server connection failed: %v", err)
		}
		if in == nil {
			continue
		}
		switch u := in.Union.(type) {
		case *pb.RendezvousMessage_PunchHoleResponse:
			ph := u.PunchHoleResponse
			if len(ph.GetSocketAddr()) == 0 {
				if err := punchHoleFailure(ph); err != nil {
					return nil, err
				}
				continue
			}
			// The peer answered with an address for a direct connection: a
			// hole punch, or its LAN address when hbbs sees us both behind
			// one public IP (FetchLocalAddr). We never connect directly; like
			// the RustDesk client after a failed direct attempt, ask hbbs to
			// put the peer on a relay ourselves.
			return clientRelay(ctx, req, ph)
		case *pb.RendezvousMessage_RelayResponse:
			r := u.RelayResponse
			if r.GetRefuseReason() != "" {
				return nil, fail(CodeRefused, "%s", r.GetRefuseReason())
			}
			if r.GetUuid() == "" {
				return nil, fail(CodeRefused, "the server sent a relay answer without a session id")
			}
			return &Ticket{UUID: r.GetUuid(), RelayServer: r.GetRelayServer(), SignedPeerKey: r.GetPk(), PeerVersion: r.GetVersion()}, nil
		}
	}
}

// clientRelay asks hbbs to send the peer to a relay under a uuid we pick
// (client.rs request_relay): a fresh connection per attempt, as hbbs wants a
// different NAT address for each.
func clientRelay(ctx context.Context, req Request, ph *pb.PunchHoleResponse) (*Ticket, error) {
	serverKey, err := crypto.ParseServerKey(req.Server.Key)
	if err != nil {
		return nil, err
	}
	id := newUUID()
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, err := wire.Dial(dctx, req.Server.IDServer, PortRendezvous, req.Server.Insecure)
		cancel()
		if err != nil {
			return nil, fail(CodeUnreachable, "cannot reach the ID server: %v", err)
		}
		t, err := func() (*Ticket, error) {
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			s := &secureConn{conn: conn}
			if !wire.IsWS(req.Server.IDServer) {
				if err := s.serverKeyExchange(serverKey, req.Server.Token != ""); err != nil {
					return nil, err
				}
			}
			out := &pb.RendezvousMessage{Union: &pb.RendezvousMessage_RequestRelay{RequestRelay: &pb.RequestRelay{
				Id:          req.PeerID,
				Token:       req.Server.Token,
				Uuid:        id,
				RelayServer: ph.GetRelayServer(),
				Secure:      true,
				ConnType:    req.ConnType,
				LicenceKey:  strings.TrimSpace(req.Server.Key),
			}}}
			if err := s.send(out); err != nil {
				return nil, fail(CodeNetwork, "ID server connection failed: %v", err)
			}
			conn.SetReadDeadline(time.Now().Add(18 * time.Second))
			for {
				in, err := s.recv()
				if err != nil {
					var ne net.Error
					if errors.As(err, &ne) && ne.Timeout() {
						return nil, fail(CodeTimeout, "the remote device did not join the relay")
					}
					return nil, fail(CodeNetwork, "ID server connection failed: %v", err)
				}
				rr := in.GetRelayResponse()
				if rr == nil {
					continue
				}
				if rr.GetRefuseReason() != "" {
					return nil, fail(CodeRefused, "%s", rr.GetRefuseReason())
				}
				pk := ph.GetPk()
				if len(rr.GetPk()) > 0 {
					pk = rr.GetPk()
				}
				relay := ph.GetRelayServer()
				if rr.GetRelayServer() != "" {
					relay = rr.GetRelayServer()
				}
				return &Ticket{UUID: id, RelayServer: relay, SignedPeerKey: pk, PeerVersion: rr.GetVersion()}, nil
			}
		}()
		if err == nil || ctx.Err() != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return t, nil
		}
		last = err
		var re *Error
		if errors.As(err, &re) && re.Code != CodeTimeout && re.Code != CodeNetwork {
			return nil, err
		}
	}
	return nil, last
}

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func punchHoleFailure(r *pb.PunchHoleResponse) error {
	if other := r.GetOtherFailure(); other != "" {
		lower := strings.ToLower(other)
		if strings.Contains(lower, "login") || strings.Contains(lower, "token") {
			return fail(CodeLoginRequired, "%s", other)
		}
		return fail(CodeRefused, "%s", other)
	}
	switch r.GetFailure() {
	case pb.PunchHoleResponse_OFFLINE:
		return fail(CodeOffline, "the remote device is offline")
	case pb.PunchHoleResponse_LICENSE_MISMATCH:
		return fail(CodeKeyMismatch, "the server key does not match")
	case pb.PunchHoleResponse_LICENSE_OVERUSE:
		return fail(CodeRefused, "the server refused the connection (licence overuse)")
	case pb.PunchHoleResponse_ID_NOT_EXIST:
		if len(r.GetSocketAddr()) == 0 && r.GetRelayServer() == "" {
			return fail(CodeNotFound, "the ID does not exist")
		}
	}
	return nil
}

// secureConn is a rendezvous connection, encrypted once hbbs' key exchange ran.
type secureConn struct {
	conn   wire.Conn
	cipher *crypto.Cipher
}

func (s *secureConn) send(m *pb.RendezvousMessage) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	if s.cipher != nil {
		b = s.cipher.Seal(b)
	}
	return s.conn.Send(b)
}

// recv returns the next message, or nil for keep-alives and junk.
func (s *secureConn) recv() (*pb.RendezvousMessage, error) {
	b, err := s.conn.Recv()
	if err != nil {
		return nil, err
	}
	if s.cipher != nil {
		if b, err = s.cipher.Open(b); err != nil {
			return nil, err
		}
	}
	if len(b) == 0 {
		return nil, nil
	}
	var m pb.RendezvousMessage
	if proto.Unmarshal(b, &m) != nil {
		return nil, nil
	}
	return &m, nil
}

// serverKeyExchange answers the signed KeyExchange hbbs sends on accept.
// required: fail rather than continue in the clear (a token is about to go
// out). Without it, a server that sends nothing within a moment is taken to
// be one without a key, as the RustDesk client does.
func (s *secureConn) serverKeyExchange(serverKey ed25519.PublicKey, required bool) error {
	wait := 2 * time.Second
	if required {
		wait = 10 * time.Second
	}
	s.conn.SetReadDeadline(time.Now().Add(wait))
	defer s.conn.SetReadDeadline(time.Time{})
	var ex *pb.KeyExchange
	for ex == nil {
		m, err := s.recv()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && !required {
				return nil
			}
			if required {
				return fail(CodeInsecure, "the ID server did not secure the connection; not sending the access token in the clear")
			}
			return fail(CodeNetwork, "ID server connection failed: %v", err)
		}
		if m == nil {
			continue
		}
		u, ok := m.Union.(*pb.RendezvousMessage_KeyExchange)
		if !ok {
			if required {
				return fail(CodeInsecure, "the ID server did not secure the connection; not sending the access token in the clear")
			}
			return fail(CodeNetwork, "unexpected first message from the ID server")
		}
		ex = u.KeyExchange
	}
	if len(ex.GetKeys()) != 1 {
		return fail(CodeKeyMismatch, "invalid key exchange message from the ID server")
	}
	theirPK, ok := crypto.SignOpen(ex.GetKeys()[0], serverKey)
	if !ok || len(theirPK) != 32 {
		return fail(CodeKeyMismatch, "the ID server's key exchange is not signed with the configured key")
	}
	// Bit 255 of the signed key marks servers that also sign the version.
	if theirPK[31]&0x80 != 0 || len(ex.GetSignedParams()) != 0 {
		signed, ok := crypto.SignOpen(ex.GetSignedParams(), serverKey)
		var params pb.KxParams
		if !ok || len(signed) < len(crypto.KxParamsDomain) || string(signed[:len(crypto.KxParamsDomain)]) != string(crypto.KxParamsDomain) ||
			proto.Unmarshal(signed[len(crypto.KxParamsDomain):], &params) != nil {
			return fail(CodeKeyMismatch, "missing or invalid signed key exchange parameters")
		}
		if string(params.GetPk()) != string(theirPK) || params.GetVersion() != ex.GetVersion() {
			return fail(CodeKeyMismatch, "key exchange version or public key does not match its signature")
		}
	}
	var their [32]byte
	copy(their[:], theirPK)
	their[31] &= 0x7F // X25519 ignores bit 255 anyway
	kx, err := crypto.NewKeyExchange(&their)
	if err != nil {
		return err
	}
	picked := crypto.KxVersionFor(ex.GetVersion())
	out := &pb.RendezvousMessage{Union: &pb.RendezvousMessage_KeyExchange{KeyExchange: &pb.KeyExchange{
		Keys:    [][]byte{kx.OurPublic[:], kx.Sealed},
		Version: picked,
	}}}
	if err := s.send(out); err != nil {
		return fail(CodeNetwork, "ID server connection failed: %v", err)
	}
	c, err := crypto.NewCipher(kx.Key, true, crypto.Transcript{
		InitiatorPK: kx.OurPublic[:],
		ResponderPK: theirPK,
		Advertised:  ex.GetVersion(),
		Picked:      picked,
	})
	if err != nil {
		return err
	}
	s.cipher = c
	return nil
}

// RelayAddress picks where to join the relay for a ticket.
func RelayAddress(srv Server, t *Ticket) string {
	if srv.Relay != "" {
		return srv.Relay
	}
	if wire.IsWS(srv.IDServer) {
		return RelayURLNextTo(srv.IDServer)
	}
	if t.RelayServer != "" {
		return wire.WithPort(t.RelayServer, PortRelay)
	}
	host := srv.IDServer
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return wire.WithPort(host, PortRelay)
}

// RelayURLNextTo maps an hbbs WebSocket URL to the hbbr one:
// wss://host/ws/id -> wss://host/ws/relay, ws://host:21118 -> ws://host:21119.
func RelayURLNextTo(idURL string) string {
	u, err := url.Parse(idURL)
	if err != nil {
		return strings.TrimSuffix(strings.TrimSuffix(idURL, "/"), "/ws/id") + "/ws/relay"
	}
	u.RawQuery, u.Fragment = "", ""
	if p, err := strconv.Atoi(u.Port()); err == nil && p == 21118 {
		u.Host = net.JoinHostPort(u.Hostname(), "21119")
		return u.String()
	}
	path := strings.TrimSuffix(u.Path, "/")
	if strings.HasSuffix(path, "/ws/id") {
		u.Path = strings.TrimSuffix(path, "/ws/id") + "/ws/relay"
	} else {
		u.Path = "/ws/relay"
	}
	return u.String()
}

// JoinRelay connects to the relay and asks to be paired for the ticket.
func JoinRelay(ctx context.Context, srv Server, t *Ticket, peerID string, connType pb.ConnType) (wire.Conn, error) {
	addr := RelayAddress(srv, t)
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, err := wire.Dial(dctx, addr, PortRelay, srv.Insecure)
	cancel()
	if err != nil {
		return nil, fail(CodeUnreachable, "cannot reach the relay server %s: %v", wire.Redact(addr), err)
	}
	msg := &pb.RendezvousMessage{Union: &pb.RendezvousMessage_RequestRelay{RequestRelay: &pb.RequestRelay{
		Id:         peerID,
		Uuid:       t.UUID,
		LicenceKey: strings.TrimSpace(srv.Key),
		Secure:     true,
		ConnType:   connType,
	}}}
	b, _ := proto.Marshal(msg)
	if err := conn.Send(b); err != nil {
		conn.Close()
		return nil, fail(CodeNetwork, "relay connection failed: %v", err)
	}
	return conn, nil
}
